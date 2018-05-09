#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

TaintMemStruct	taint_mem_;
TaintRegStruct  taint_reg_;
instrFunc		instrFunctions[MAX_OPCODE];
Fd_entity 		fds_[MAX_FD];
enum mode 		started_ 						= MODE_BEFORE_MAIN; //MODE_BEFORE_MAIN MODE_ACTIVE MODE_IGNORING
Eflags          eflags_;

UID_entity		uids_[MAX_UID];
ID_entity		ids_[MAX_ID];
IID_entity      iids_[MAX_IID];

// Used to describe true taint sources (e.g. read())
int				nextUID							= 1;

// Used to describe taint and operations
int 			nextID							= 1;

// Used to describe which ID memory has, of what size and which index
int 			nextIID							= 1;



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
    ids_[newid].ops[i].is_id = ids_[id].ops[i].is_id;
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

// If correct sizing tainted - return
// If none of sizings tainted - return -1
// If one of the sizings tainted - make new taint id, of correct size and return.
// !!!! WE IGNORE CASE IF e.g. this int's second half is tainted as first half of another int  !!!!!!
int nshr_reg_get_or_fix_sized_taint(int reg)
{
  int index = SIZE_TO_INDEX(REGSIZE(reg));

  // case 1. 
  int iid = REGTAINTVAL(reg, 0, index);

  if (iid > 0)
  {
    if (IID2INDEX(iid) != 0)
    {
    	FAIL();
    }

  	return IID2ID(iid);
  }

  int id = nshr_reg_taint_any(reg);

  // case 2.
  if (id == -1) return -1;

  // Make new taint.

  int newid = nshr_tid_new_id();

  ids_[newid].uid      = ID2UID(id);
  ids_[newid].ops_size = 0;
  ids_[newid].size     = REGSIZE(reg);

  LDEBUG("Utils:\t\tFIXING SIZE: Created new id %d from uid %d size %d.\n", newid, ids_[newid].uid, REGSIZE(reg));

  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
    int newiid = nshr_tid_new_iid(newid, i);

    if (i == 0)
    {
      LDEBUG("Utils:\t\tCreated new iid %d for reg %s byte %d, to id %d size %d index %d\n", 
              newiid, REGNAME(reg), REGSTART(reg) + i, newid, ID2SIZE(newid), IID2INDEX(newiid));
    }

    SETREGTAINTVAL(reg, i, index, newiid);
  }

  return newid;
}


int nshr_tid_modify_id_by_symbol(int dst_taint, int byte, enum prop_type operation, int src_taint)
{
  int newid = nshr_tid_copy_id(dst_taint);

  ID2OP(newid, ID2OPSIZE(newid)).type  = operation;
  ID2OP(newid, ID2OPSIZE(newid)).is_id = 1;
  ID2OP(newid, ID2OPSIZE(newid)).value = src_taint;

  ID2OPSIZE(newid)++;

  LDEBUG("Utils:\t\tAppended operation '%s' to id %d by ID#%d.\n", PROP_NAMES[operation], newid, src_taint);

  return nshr_tid_new_iid(newid, 0);
}

int nshr_tid_new_uid(int fd)
{
  uids_[nextUID].fd       = fd;
  uids_[nextUID].bounded  = 0;

  int newid  = nshr_tid_new_id();
  int newiid = nshr_tid_new_iid(newid, 0);

  ids_[newid].uid          = nextUID;
  ids_[newid].ops_size     = 0;
  ids_[newid].size         = 1;

  nextUID++;

  return newiid;
}

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data)
{
  const char *format = (const char *) drwrap_get_arg(wrapcxt, 0);

  LTEST("DRWRAP:\t\tGoing into scanf.\n");

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
    FAIL();
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
  	FAIL();
  }

  return copy;
}

reg_t decode_addr(int seg_reg, int base_reg, int index_reg, int scale, int disp)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP("DECODED: base %p index %d scale %d disp %d.\n", 
  	                 base, index, scale, disp);

  return addr;
}

void update_eflags(int opcode, int index, int t1, int t2)
{
	eflags_.type = opcode;

	eflags_.taint1[index] = t1;
	eflags_.taint2[index] = t2;

	eflags_.valid = 1;
}

void invalidate_eflags()
{
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
      	int uid = ID2UID(ids[i]);

      	if (ID2OPSIZE(ids[i]) > 0)
      	{
      	  FAIL();
      	}
        
        if (i == 0)
        {
  		  LTEST("Bounder:\t\tBounding Taint ID#%d (UID#%d) by mask %d.\n", ids[i], uid, mask);
  		}

	    uids_[uid].bounded |= mask;
      }
    }
}

void check_bounds(int reg)
{
  if (reg == DR_REG_NULL)
  {
  	return;
  }

  for (unsigned int i = 0; i < REGSIZE(reg); i++)
  {
  	int t = REGTAINTVAL1(reg, i);

  	if (t > 0)
  	{
      int uid = ID2UID(t);

      if ((uids_[uid].bounded & (TAINT_BOUND_LOW | TAINT_BOUND_FIX)) == 0)
      {
        LWARNING("!!!WARNING!!! ID#%d (UID#%d) is not bound from below!!\n", t, uid);
      }

      if ((uids_[uid].bounded & (TAINT_BOUND_HIGH | TAINT_BOUND_FIX)) == 0)
      {
        LWARNING("!!!WARNING!!! ID#%d (UID#%d) is not bound from up!!\n", t, uid);
      }
  	}
  }
}
