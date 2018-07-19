#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

TaintMemStruct  taint_mem_;
TaintRegStruct  taint_reg_;
instrFunc       instrFunctions[MAX_OPCODE];
enum mode       started_                     = MODE_BEFORE_MAIN; //MODE_BEFORE_MAIN MODE_ACTIVE MODE_IGNORING
Eflags          eflags_;

UID_entity      uid_[MAX_UID];
ID_entity       tid_[MAX_ID];

hashtable_t FILEs_;
int         fds_[MAX_FD];

Fd_entity   files_history_[MAX_FILE_HISTORY];
Fd_entity fds_history_[MAX_FILE_HISTORY];
uint64_t files_history_index_                = 1;  // Why 1? try 0.
uint64_t fds_history_index_                  = 0;


hashtable_t func_hashtable;


// Used to describe true taint sources (e.g. read())
int             nextUID                      = 1;

// Used to describe taint and operations
int             nextID                       = 1;

// Used to describe which ID memory has, of what size and which index
int             nextIID                      = 1;


lprec           *lp;

instr_t *instr_pointers[INSTR_DUPL_SIZE];
int instr_next_pointer = 0;

file_t logfile, dumpfile;
FILE * logfile_stream;

app_pc main_address;

app_pc tmp_addr;
app_pc return_to;

app_pc ignore_vector[64];
int ignore_vector_size                       = 0;

void add_ignore_func(app_pc pc)
{
  if (pc == NULL)
  {
    FAIL();
  }

  ignore_vector[ignore_vector_size++] = pc;
}

int check_ignore_func(app_pc pc)
{
  for (int i = 0; i < ignore_vector_size; i++)
    if (ignore_vector[i] == pc) return 1;

  return 0;
}


const char *manual_taint_path  = "<manually tainted>";
const char *cmd_arg_taint_path = "<command line>";

void add_bound(int uid, int mask)
{
  uid_[uid].bounded |= mask;
}

int prop_is_binary(enum prop_type type )
{
  return type >= PROP_ADD && type <= PROP_IMUL;
}

int prop_is_mov(enum prop_type type )
{
  return type == PROP_MOV || type == PROP_MOVZX || type == PROP_MOVSX;
}

int prop_is_restrictor(enum prop_type type )
{
  return type >= PROP_OR && type <= PROP_AND;
}

int prop_is_cond_mov(enum prop_type type )
{
  return type >= COND_LESS && type <= COND_NOT_SIGN_BIT;
}

int nshr_tid_new_id(int uid)
{
  tid_[nextID].uid      = uid;
  tid_[nextID].ops_size = 0;
  tid_[nextID].negated  = 0;

  if (nextID >= MAX_ID)
  {
    FAIL();
  }

  return nextID++;
}

int nshr_tid_new_id_get()
{
  return nextID;
}

int nshr_tid_new_uid_get()
{
  return nextUID;
}

int nshr_tid_copy_id(int id)
{
  int newid = nshr_tid_new_id(tid_[id].uid);

  LDEBUG("Utils:\t\tCopied id %d to %d.\n", id, newid);

  /*
  First copy everything from old id.
  */

  tid_[newid].ops_size = tid_[id].ops_size;
  tid_[newid].negated  = tid_[id].negated;
  tid_[newid].size     = tid_[id].size;

  int i;

  for (i = 0; i < tid_[id].ops_size; i++)
  {
    tid_[newid].ops[i].type  = tid_[id].ops[i].type;
    tid_[newid].ops[i].value = tid_[id].ops[i].value;
  }

  return newid;
}

void nshr_id_add_op(int id, enum prop_type operation, int modify_by)
{
  // FIXME: Problem with those is we should take prop_type into consideration.
  //        e.g. what if it was added, and now we are subtracting?
  //        many cases to consider, will make things way faster.

  if (modify_by == -1)
  {
    return;
  }
  
  // First make sure id is not already in operations list;
  for (int i = 0; i < ID2OPSIZE(id); i++)
  {
    if (ID2OP(id, i).value == modify_by &&
        ID2OP(id, i).type  == PROP_ADD &&
        operation == PROP_ADD) return;
  }

  ID2OP(id, ID2OPSIZE(id)).type  = operation;
  ID2OP(id, ID2OPSIZE(id)).value = modify_by;

  ID2OPSIZE(id)++;

  if (ID2OPSIZE(id) >= DEFAULT_OPERATIONS)
  {
    FAIL();
  }
}

static int lower_bound(int uid)
{
  if ((uid_[uid].bounded & (TAINT_BOUND_LOW | TAINT_BOUND_FIX)) == 0)
  {
    return 0;
  }

  return 1;
}

static int higher_bound(int uid)
{
  if ((uid_[uid].bounded & (TAINT_BOUND_HIGH | TAINT_BOUND_FIX)) == 0)
  {
    return 0;
  }

  return 1;
}


// first copy to a teporary register.
int nshr_make_id_by_merging_all_ids(int *ids1, int *ids2)
{
  // First, make sure at least one of them is tainted.
  int tainted = 0;
  int uid     = -1;

  for(unsigned int i = 0; i < 8; i++)
  {
    if (ids1[i] > 0)
    {
      tainted = 1;
      uid = ID2UID(ids1[i]);
    }
    else if (ids2[i] > 0)
    {
      tainted = 1;
      uid = ID2UID(ids2[i]);
    }
  }

  if (tainted == 0)
  {
    return -1;
  }

  int newid = nshr_tid_new_id(uid);

  for(unsigned int i = 0; i < 8; i++)
  {
    if (ids1[i] > 0)
    {
      nshr_id_add_op(newid, PROP_ADD, ids1[i]);
    }

    if (ids2[i] > 0)
    {
      nshr_id_add_op(newid, PROP_ADD, ids2[i]);
    }
  }

  return newid;
}

int nshr_tid_modify_id_by_symbol(int dst_taint, enum prop_type operation, int src_taint)
{
  int newid = nshr_tid_copy_id(dst_taint);

  nshr_id_add_op(newid, operation, src_taint);

  LDEBUG("Utils:\t\tAppended operation '%s' to id %d by ID#%d.\n", PROP_NAMES[operation], newid, src_taint);

  return newid;
}

int nshr_tid_new_uid_by_file(int file)
{
  uid_[nextUID].descriptor.file = file;
  uid_[nextUID].descr_type      = 1;
  uid_[nextUID].bounded         = 0;
  uid_[nextUID].gr              = NULL;

  int newid  = nshr_tid_new_id(nextUID);

  tid_[newid].size         = 1;

  nextUID++;

  if (nextUID >= MAX_UID)
  {
    FAIL();
  }

  return newid;
}

int nshr_tid_new_uid_by_fd(int fd)
{
  uid_[nextUID].descriptor.fd = fd;
  uid_[nextUID].descr_type    = 0;
  uid_[nextUID].bounded       = 0;
  uid_[nextUID].gr            = NULL;

  int newid  = nshr_tid_new_id(nextUID);

  tid_[newid].size         = 1;

  nextUID++;

  if (nextUID >= MAX_UID)
  {
    FAIL();
  }

  return newid;
}

int mem_taint_is_empty(int index, uint64_t addr)
{
  return (taint_mem_.value[index][(addr) % TAINTMAP_SIZE] == -1);
}  

uint64_t mem_taint_get_addr(int index, uint64_t addr)
{
  return taint_mem_.address[index][(addr) % TAINTMAP_SIZE];
}

void mem_taint_set_addr(int index, uint64_t addr, uint64_t value)
{
  taint_mem_.address[index][(addr) % TAINTMAP_SIZE] = value;
}

int64_t mem_taint_get_value(int index, uint64_t addr)
{
  return taint_mem_.value[index][(addr) % TAINTMAP_SIZE];
}

void mem_taint_set_value(int index, uint64_t addr, uint64_t value)
{
  taint_mem_.address[index][(addr) % TAINTMAP_SIZE]     = addr;
  taint_mem_.value[index][(addr) % TAINTMAP_SIZE]       = value;
}

int mem_taint_find_index(uint64_t addr, int i)
{
  int index = 0;

  while(!mem_taint_is_empty(index, addr + i) && 
            mem_taint_get_addr(index, addr + i) != addr + i &&
                index < TAINTMAP_NUM)
  {
    index++;
  }

  if (index == TAINTMAP_NUM)
  {
    DIE("ERROR! Shadow memory failure at [A]\n");
  }

  return index;
}


char    reg_get_byte_value(int reg, int offset)
{
  GET_CONTEXT();
  
  char *pc = (char *) reg_get_value(reg, &mcontext);

  return pc[offset];
}

uint64_t    reg_get_full_value(int reg)
{
  GET_CONTEXT();
  
  uint64_t r = (uint64_t) reg_get_value(reg, &mcontext);

  return r;
}

int64_t reg_taint_get_value(int reg, int offset)
{
  return taint_reg_.value[REGINDEX(reg)][REGSTART(reg) + offset];
}

void    reg_taint_set_value(int reg, int offset, uint64_t value)
{
  taint_reg_.value[REGINDEX(reg)][REGSTART(reg) + offset] = value;
}

void reg_taint_rm_all(int reg)
{
  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    REGTAINTRM(reg, i);
  } 
}

void mem_taint_rm_all(uint64_t addr, int size)
{
  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    MEMTAINTRM(index, addr + i);
  }
}

int mem_taint_any(uint64_t addr, int size)
{
  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    if (MEMTAINTED(index, addr + i))
    {
      return 1;
    }
  }

  return 0;
}

int reg_taint_any(int reg)
{
  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    if (REGTAINTED(reg, i))
    {
      return 1;
    }
  }

  return 0;
}


void log_instr(instr_t *instr)
{
  int opcode = instr_get_opcode(instr);

  void *drcontext = dr_get_current_drcontext();

  char str[64];

  instr_disassemble_to_buffer(drcontext, instr, str, 64);

  dr_fprintf(logfile, "[%llx] TAINT! %s: ", instr_get_app_pc(instr), str);

  return;
}

instr_t *instr_dupl(instr_t *instr)
{
  instr_t *copy = instr_clone(dr_get_current_drcontext(), instr);

  instr_pointers[instr_next_pointer++] = copy;

  if (instr_next_pointer >= INSTR_DUPL_SIZE)
  {
    DIE("ERROR! instr. dupl. failure at [A]\n");
  }

  return copy;
}


drsym_info_t *get_func(app_pc pc)
{
  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
    return NULL;
  }

  static drsym_info_t sym;

  char name_buf[1024];
  char file_buf[1024];

  sym.struct_size = sizeof(sym);
  sym.name = name_buf;
  sym.name_size = 1024;
  sym.file = file_buf;
  sym.file_size = 1024;

  drsym_error_t symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

  dr_free_module_data(data);

  if (symres != DRSYM_SUCCESS)
  {
    return NULL;
  }

  return &sym;
}

void *get_tls_at_offset(int off)
{
  GET_CONTEXT();

  dr_switch_to_app_state(drcontext);

  uint64_t a;
  
  asm volatile ("mov    %%fs:0x0, %%rax" :"=a" (a) :: );

  dr_switch_to_dr_state(drcontext);

  a += off;

  return (void *) a;
}


reg_t decode_addr(int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(base_reg  DGB_END_CALL_ARG);
  check_bounds_reg(index_reg DGB_END_CALL_ARG);

  GET_CONTEXT();

  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  if (seg_reg != DR_REG_NULL)
  {
    FAILIF(seg_reg != DR_SEG_FS);

    reg_t segoff = (reg_t ) get_tls_at_offset(addr);

    addr += segoff;
  }

  LDUMP("Decoder:\t\tDecoded base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  return addr;
}

void update_eflags(int opcode, int index, int t1, int t2)
{
  LTEST("EFLAGS:\t\tUpdating eflags with opcode %d index %d t1 %d t2 %d.\n", opcode, index, t1, t2);

  eflags_.type = opcode;

  eflags_.taint1[index] = t1;
  eflags_.taint2[index] = t2;

  eflags_.valid = 1;
}


void clear_eflags()
{
  for (int i = 0; i < 8; i++)
  {
    eflags_.taint1[i] = -1;
    eflags_.taint2[i] = -1;
  }
}

void invalidate_eflags()
{
  LDUMP("EFLAGS:\t\tInvalidating eflags.\n");

  eflags_.valid = 0;
}

int is_valid_eflags()
{
  return eflags_.valid;
}


int get_eflags_type()
{
  return eflags_.type;
}

int *get_taint1_eflags()
{
  if (!is_valid_eflags()) return NULL;

  for (int i = 0; i < 8; i++)
  {
    if (eflags_.taint1[i] > 0)
    {
      return eflags_.taint1;
    }
  }

  return NULL;
}

int *get_taint2_eflags()
{
  if (!is_valid_eflags()) return NULL;

  for (int i = 0; i < 8; i++)
  {
    if (eflags_.taint2[i] > 0)
    {
      return eflags_.taint2;
    }
  }

  return NULL;
}

void bound2(int *ids1, int *ids2, int type)
{
  for (int i = 0; i < 8; i++)
  {
    if (ids1[i] != -1 || ids2[i] != -1)
    {
      int id;
      Group_restriction *gr = (Group_restriction *) malloc(sizeof(Group_restriction));

      if (type == COND_LESS || type == COND_LESS_UNSIGNED)
      {
        // ids1 < ids2 is same as ids1 - ids2 is bound from above.
        if (ids1[i] > 0)
        {
          id = nshr_tid_copy_id(ids1[i]);

          nshr_id_add_op(id, PROP_SUB, ids2[i]);

          gr -> bound_type = TAINT_BOUND_HIGH;
        }
        // imm < ids2 is same as ids2 is bound from below
        else
        {
          id = ids2[i];

          gr -> bound_type = TAINT_BOUND_LOW;
        }
      }
      // ids1 == ids2 can be interpreted as ids1 - ids2 is fixed.
      else if (type == COND_EQ)
      {
        gr -> bound_type = TAINT_BOUND_FIX;

        if (ids1[i] > 0)
        {
          id = nshr_tid_copy_id(ids1[i]);

          nshr_id_add_op(id, PROP_SUB, ids2[i]);
        }
        else
        {
          id = ids2[i];
        }
      }
      else
      {
        FAIL();
      }

      gr -> id = id;
      gr -> next = uid_[ID2UID(id)].gr;

      uid_[ID2UID(id)].gr = gr;
    }
    else
    {
      // Nothing.
    }
  }
}

void bound(int *ids, int mask)
{
  for (int i = 0; i < 8; i++)
  {
    if (ids[i] != -1)
    {
      int id = ids[i];
      int uid = ID2UID(id);

      if (ID2OPSIZE(id) > 0)
      {
        Group_restriction *gr = (Group_restriction *) malloc(sizeof(Group_restriction));
        gr -> id = id;
        gr -> bound_type = mask;
        gr -> next = uid_[uid].gr;

        uid_[uid].gr = gr;

        if (i == 0)
        {
          LTEST("Bounder:\t\tCreated new group restriction on TAINT#%d to uid %d.\n", id, uid);
        }
      }
      else
      {
        if (i == 0)
        {
          LTEST("Bounder:\t\tBounding Taint ID#%d (UID#%d) by mask %d.\n", ids[i], uid, mask);
        }

        add_bound(uid, mask);
      }
    }
  }
}

// Returns: -1 on vulnerability
//           1 on safe
//           0 on could not decide
int check_bounds_separately(int *ids DBG_END_TAINTING_FUNC)
{
  int vulnerables = 0;
  int tainted_ids = 0;
  int well_bounds = 0;

  for (int i = 0; i < 8; i++)
  {
    int id = ids[i];

    if (id == -1)
    {
      continue;
    }

    tainted_ids++;

    int uid = ID2UID(id);

    int vuln1 = 0;
    int vuln2 = 0;

    if (!lower_bound(uid) || !higher_bound(uid))
    {
      vuln1 = 1;
    }

    for (int i = 0; i < ID2OPSIZE(id); i++)
    {
      int tuid = ID2OP(id, i).value;

      if (!lower_bound(uid) || !higher_bound(uid))
      {
        vuln2 = 1;
      }
    }

    // all participants are well bound.
    if (vuln1 == 0 && vuln2 == 0)
    {
      well_bounds++;

      continue;
    }

    // only one uid participating, it's not bounded and there are no related group restrictions....
    if (ID2OPSIZE(id) == 0 && vuln1 == 1 && uid_[ID2UID(id)].gr == NULL)
    {
      vulnerables++;
    }
  }

  if (vulnerables >= MIN_VULNERABILITIES)
  {
    return -1;
  }
  else if (tainted_ids == well_bounds)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

void vulnerability_detected()
{
  dump();

  // Whatever we wanna do if we detect it.
  exit(0);
}

int check_bounds_id(int *ids DBG_END_TAINTING_FUNC)
{
  int separate = check_bounds_separately(ids DGB_END_CALL_ARG);

  if (separate == 0)
  {
    return solve_ilp(ids DGB_END_CALL_ARG);
  }
  else
  {
    return separate;
  }
}

void check_bounds_mem(uint64_t addr, int size DBG_END_TAINTING_FUNC)
{
  if (MEMTAINTEDANY(addr, size))
  {
    int ids[8];

    get_mem_taint(addr, size, ids);

    int bounded = check_bounds_id(ids DGB_END_CALL_ARG);

    if (bounded == -1)
    {
      #ifdef DBG_PASS_INSTR
      drsym_info_t *func = get_func(instr_get_app_pc(dbg_instr));
      LERROR("!!!VULNERABILITY!!! ILP Detected unbounded access at %s  %s:%d\n", 
                       func -> name, func -> file, func -> line);
      #else
      LERROR("!!!VULNERABILITY!!! ILP Detected unbounded access\n");
      #endif

      LERROR("Participating ids: ");
      for (int i = 0; i < 8; i++) LERROR("%d, ", ids[i]);
      LERROR("\n");

      vulnerability_detected();
    }
  }
}

void check_bounds_reg(int reg DBG_END_TAINTING_FUNC)
{
  if (reg == DR_REG_NULL)
  {
    return;
  }

  if (REGTAINTEDANY(reg))
  {
    int ids[8];

    get_reg_taint(reg, ids);

    int bounded = check_bounds_id(ids DGB_END_CALL_ARG);

    if (bounded == -1)
    {
      #ifdef DBG_PASS_INSTR
      drsym_info_t *func = get_func(instr_get_app_pc(dbg_instr));
      if (func != NULL)
      {
        LERROR("!!!VULNERABILITY!!! ILP Detected unbounded access at %s  %s:%d\n", 
                         func -> name, func -> file, func -> line);
      }
      else
      {
        LERROR("!!!VULNERABILITY!!! ILP Detected unbounded access\n");
      }
      #else
      LERROR("!!!VULNERABILITY!!! ILP Detected unbounded access\n");
      #endif

      LERROR("Participating ids: ");
      for (int i = 0; i < 8; i++) LERROR("%d, ", ids[i]);
      LERROR("\n");

      vulnerability_detected();
    }
  }
}

uint64_t low_trim(uint64_t data, int size)
{
  uint64_t s = 1;
  s = s << size;
  s--;

  data = data & s;

  return data; 
}

void get_reg_taint(int reg, int *ids)
{
  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    ids[i] = REGTAINTVAL(reg, i);
  }

  for (unsigned int i = REGSIZE(reg); i < 8; i++)
  {
    ids[i] = -1;
  }
}

void set_reg_taint(int reg, int *ids)
{
  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    SETREGTAINTVAL(reg, i, ids[i]);
  }
}

void get_mem_taint(uint64_t addr, int size, int *ids)
{
  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    ids[i] = MEMTAINTVAL(index, addr + i);
  }

  for (unsigned int i = size; i < 8; i++)
  {
    ids[i] = -1;
  }
}

void set_mem_taint(uint64_t addr, int size, int *ids)
{
  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    SETMEMTAINTVAL(index, addr + i, ids[i]);
  }
}

void hashtable_del_entry(void *p)
{
/*
  handleFunc *e = (handleFunc *) p;

  free((char *) (e[2]));
  free(p);
  */
}


int is_path_secure(const char *path)
{
  // They are used for crypto-computations,
  // if we taint them they will go under complicated taint propagtions
  // but will never be used to access mem. Thus, let's assume they are secure.
  if (strcmp(path, "/dev/urandom") == 0 ||
      strcmp(path, "/dev/random") == 0)
  {
    return 1;
  }

  return 0;
}

void log_location(app_pc pc)
{
  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
     dr_printf("dr_lookup_module failed for %llx.\n", pc);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  drsym_info_t sym;

  char name_buf[1024];
  char file_buf[1024];

  sym.struct_size = sizeof(sym);
  sym.name = name_buf;
  sym.name_size = 1024;
  sym.file = file_buf;
  sym.file_size = 1024;
    
  drsym_error_t symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

  if (symres == DRSYM_SUCCESS)
  {
    dr_printf("Looked up address at %s[%s] at %s %s:%d.\n", sym.name, modname, data -> full_path, sym.file, sym.line);
  }
  else
  {
    dr_printf("Looked up address at  [%s] at %s.\n", modname, data -> full_path);
  }
}

int get_shift_type(int opcode)
{
  switch(opcode)
  {
    case OP_shl:    return LOGICAL_LEFT;
    case OP_shr:    return LOGICAL_RIGHT;
    case OP_sar:    return ARITH_RIGHT;
    case OP_rol:    return ROTATE_LEFT;
    case OP_ror:    return ROTATE_RIGHT;
    default:        FAIL();
  }

}