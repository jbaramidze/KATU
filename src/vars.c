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
Fd_entity       fds_[MAX_FD];
enum mode       started_                     = MODE_BEFORE_MAIN; //MODE_BEFORE_MAIN MODE_ACTIVE MODE_IGNORING
Eflags          eflags_;

UID_entity      uids_[MAX_UID];
ID_entity       ids_[MAX_ID];
IID_entity      iids_[MAX_IID];

// Used to describe true taint sources (e.g. read())
int             nextUID                      = 1;

// Used to describe taint and operations
int             nextID                       = 1;

// Used to describe which ID memory has, of what size and which index
int             nextIID                      = 1;


lprec           *lp;

#ifdef DBG_PASS_INSTR

instr_t *instr_pointers[1024*16];
int instr_next_pointer = 0;

#endif

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

int nshr_tid_new_id()
{
  return nextID++;
}

int nshr_tid_new_iid(int id, int index)
{
  iids_[nextIID].id    = id;
  iids_[nextIID].index = index;

  return nextIID++;
}

int nshr_tid_new_id_get()
{
  return nextID;
}

int nshr_tid_new_iid_get()
{
  return nextIID;
}

int nshr_tid_copy_id(int id)
{
  int newid = nshr_tid_new_id();

  LDEBUG("Utils:\t\tCopied id %d to %d.\n", id, newid);

  /*
  First copy everything from old id.
  */

  ids_[newid].uid      = ids_[id].uid;
  ids_[newid].ops_size = ids_[id].ops_size;
  ids_[newid].size     = ids_[id].size;

  int i;

  for (i = 0; i < ids_[id].ops_size; i++)
  {
    ids_[newid].ops[i].type  = ids_[id].ops[i].type;
    ids_[newid].ops[i].value = ids_[id].ops[i].value;
  }

  return newid;
}


// Return if any byte in reg is tainted.
int nshr_reg_taint_any(int reg)
{
  int size = REGSIZE(reg);

  for (int i = 0; i < size; i++)
  {
    if (REGTAINTVAL8(reg, 0) > 0) return IID2ID(REGTAINTVAL8(reg, 0));
    if (REGTAINTVAL4(reg, 0) > 0) return IID2ID(REGTAINTVAL4(reg, 0));
    if (REGTAINTVAL2(reg, 0) > 0) return IID2ID(REGTAINTVAL2(reg, 0));
    if (REGTAINTVAL1(reg, 0) > 0) return IID2ID(REGTAINTVAL1(reg, 0));
  }

  return -1;
}

int nshr_tid_modify_id_by_symbol(int dst_taint, int byte, enum prop_type operation, int src_taint)
{
  int newid = nshr_tid_copy_id(dst_taint);

  ID2OP(newid, ID2OPSIZE(newid)).type  = operation;
  ID2OP(newid, ID2OPSIZE(newid)).value = src_taint;

  ID2OPSIZE(newid)++;

  LDEBUG("Utils:\t\tAppended operation '%s' to id %d by ID#%d.\n", PROP_NAMES[operation], newid, src_taint);

  return nshr_tid_new_iid(newid, 0);
}

int nshr_tid_new_uid(int fd)
{
  uids_[nextUID].fd       = fd;
  uids_[nextUID].bounded  = 0;
  uids_[nextUID].gr       = NULL;

  int newid  = nshr_tid_new_id();
  int newiid = nshr_tid_new_iid(newid, 0);

  ids_[newid].uid          = nextUID;
  ids_[newid].ops_size     = 0;
  ids_[newid].size         = 1;

  nextUID++;

  return newiid;
}

static uint64_t *string_args[10];
static int num_string_args;

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data)
{
  num_string_args = 1;

  const char *format = (const char *) drwrap_get_arg(wrapcxt, 0);

  LTEST("DRWRAP:\t\tGoing into scanf with %s.\n", format);

  for (unsigned int i = 0; i < strlen(format) - 1; i++)
  {
  	if (format[i] == '%')
  	{
  	  if (format[i+1] == '*')
  	  {
        num_string_args++;
        i++;
  	  }

  	  // ignore width specifier.
  	  while(isdigit(format[i+1]))
  	  {
        i++;
  	  }

  	  if (format[i+1] == 'd')
  	  {
  	  	dr_printf("gotcha!.\n\n\n");

        int *f = (int *) drwrap_get_arg(wrapcxt, num_string_args);

        nshr_taint((reg_t) &f, 4, 0);
  	  }
  	}
  }

  started_ = MODE_IN_LIBC;
}

void nshr_post_scanf(void *wrapcxt, void *user_data)
{

}

int mem_taint_is_empty(int index, uint64_t addr)
{
  return (taint_mem_.value[index][(addr) % TAINTMAP_SIZE][0] == -1 && 
          taint_mem_.value[index][(addr) % TAINTMAP_SIZE][1] == -1 && 
          taint_mem_.value[index][(addr) % TAINTMAP_SIZE][2] == -1 && 
          taint_mem_.value[index][(addr) % TAINTMAP_SIZE][3] == -1);
}  

uint64_t mem_taint_get_addr(int index, uint64_t addr)
{
  return taint_mem_.address[index][(addr) % TAINTMAP_SIZE];
}

void mem_taint_set_addr(int index, uint64_t addr, uint64_t value)
{
  taint_mem_.address[index][(addr) % TAINTMAP_SIZE] = value;
}

int64_t mem_taint_get_value(int index, uint64_t addr, int size)
{
  return taint_mem_.value[index][(addr) % TAINTMAP_SIZE][size];
}

void mem_taint_set_value(int index, uint64_t addr, int size, uint64_t value)
{
  taint_mem_.address[index][(addr) % TAINTMAP_SIZE]     = addr;
  taint_mem_.value[index][(addr) % TAINTMAP_SIZE][size] = value;
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

int64_t reg_taint_get_value(int reg, int offset, int size)
{
  return taint_reg_.value[REGINDEX(reg)][REGSTART(reg) + offset][size];
}

void    reg_taint_set_value(int reg, int offset, int size, uint64_t value)
{
  taint_reg_.value[REGINDEX(reg)][REGSTART(reg) + offset][size] = value;
}


void log_instr(instr_t *instr)
{
  int opcode = instr_get_opcode(instr);

  void *drcontext = dr_get_current_drcontext();

  char str[64];

  instr_disassemble_to_buffer(drcontext, instr, str, 64);

  dr_printf("TAINT! %s: ", str);

  return;
}

instr_t *instr_dupl(instr_t *instr)
{
  instr_t *copy = instr_clone(dr_get_current_drcontext(), instr);

  instr_pointers[instr_next_pointer++] = copy;

  if (instr_next_pointer >= 1024*16)
  {
    DIE("ERROR! instr. dumpl. failure at [A]\n");
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


reg_t decode_addr(int seg_reg, int base_reg, int index_reg, int scale, int disp)
{
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
  LDUMP("EFLAGS:\t\tUpdating eflags with opcode %d index %d t1 %d t2 %d.\n", opcode, index, t1, t2);

  eflags_.type = opcode;

  eflags_.taint1[index] = t1;
  eflags_.taint2[index] = t2;

  eflags_.valid = 1;
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
        gr -> next = uids_[uid].gr;

        uids_[uid].gr = gr;
      }
      else
      {
        if (i == 0)
        {
          LTEST("Bounder:\t\tBounding Taint ID#%d (UID#%d) by mask %d.\n", ids[i], uid, mask);
        }

        uids_[uid].bounded |= mask;
      }
    }
  }
}

static int lower_bound(int uid)
{
  if ((uids_[uid].bounded & (TAINT_BOUND_LOW | TAINT_BOUND_FIX)) == 0)
  {
    return 0;
  }

  return 1;
}

static int higher_bound(int uid)
{
  if ((uids_[uid].bounded & (TAINT_BOUND_HIGH | TAINT_BOUND_FIX)) == 0)
  {
    return 0;
  }

  return 1;
}

// Returns: -1 on vulnerability
//           1 on safe
//           0 on could not decide
int check_bounds_separately(int id DBG_END_TAINTING_FUNC)
{
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
    return 1;
  }

  // only one uid participating, and it's not bounded.
  if (ID2OPSIZE(id) == 0 && vuln1 == 1)
  {
    #ifdef DBG_PASS_INSTR
    drsym_info_t *func = get_func(instr_get_app_pc(instr));
    LWARNING("!!!WARNING!!! Detected unbounded access for ID#%d (UID#%d), at %s  %s:%d\n", 
    	              id, ID2UID(id), func -> name, func -> file, func -> line);
    #else
    LWARNING("!!!WARNING!!! Detected unbounded access for ID#%d (UID#%d)\n", id, ID2UID(id));
    #endif

    vulnerability_detected();

  	return -1;
  }

  return 0;
}

void vulnerability_detected()
{
  // Whatever we wanna do if we detect it.
  exit(0);
}

void check_bounds_id(int id DBG_END_TAINTING_FUNC)
{
  if (check_bounds_separately(id DGB_END_CALL_ARG) != 0) // if 0 we need ILP to solve.
  {
    return;
  }
  else
  {
    solve_ilp(id DGB_END_CALL_ARG);
  }
}

void check_bounds_mem(uint64_t addr, int size DBG_END_TAINTING_FUNC)
{
  for (int i = 0; i < size; i++)
  {
  	int index = mem_taint_find_index(addr, i);

  	int id = MEMTAINTVAL1(index, addr + i);

    if (id > 0)
    {
      check_bounds_id(id DGB_END_CALL_ARG);
    }
  }
}

void check_bounds_reg(int reg DBG_END_TAINTING_FUNC)
{
  if (reg == DR_REG_NULL)
  {
    return;
  }

  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    int id = REGTAINTVAL1(reg, i);
  
    if (id > 0)
    {
      check_bounds_id(id DGB_END_CALL_ARG);
    }
  }
}
