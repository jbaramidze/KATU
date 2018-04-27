#define LOGTEST
#define LOGDEBUG
#define LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

TaintMemStruct	taint_mem_;
TaintRegStruct  taint_reg_;
instrFunc		instrFunctions[MAX_OPCODE];
Fd_entity 		fds_[MAX_FD];
enum mode 		started_ 						= MODE_IGNORING;

UID_entity		uids_[MAX_UID];
ID_entity		ids_[MAX_ID];
IID_entity      iids_[MAX_IID];

// Used to describe true taint sources (e.g. read())
int				nextUID							= 1;

// Used to describe taint and operations
int 			nextID							= 1;

// Used to describe which ID memory has, of what size and which index
int 			nextIID							= 1;



int is_binary(enum prop_type type )
{
  return type >= PROP_ADD;
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

  LDUMP("Utils:\t\tCopied id %d to %d.\n", id, newid);

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

  if (size == 8)
  {
  	if (REGTAINTVAL8(reg, 0) > 0) return IID2ID(REGTAINTVAL8(reg, 0));

  	if (REGTAINTVAL4(reg, 0) > 0) return IID2ID(REGTAINTVAL4(reg, 0));
    if (REGTAINTVAL4(reg, 1) > 0) return IID2ID(REGTAINTVAL4(reg, 1));
    if (REGTAINTVAL4(reg, 2) > 0) return IID2ID(REGTAINTVAL4(reg, 2));
    if (REGTAINTVAL4(reg, 3) > 0) return IID2ID(REGTAINTVAL4(reg, 3));
    if (REGTAINTVAL4(reg, 4) > 0) return IID2ID(REGTAINTVAL4(reg, 4));

    if (REGTAINTVAL2(reg, 0) > 0) return IID2ID(REGTAINTVAL2(reg, 0));
    if (REGTAINTVAL2(reg, 1) > 0) return IID2ID(REGTAINTVAL2(reg, 1));
    if (REGTAINTVAL2(reg, 2) > 0) return IID2ID(REGTAINTVAL2(reg, 2));
    if (REGTAINTVAL2(reg, 3) > 0) return IID2ID(REGTAINTVAL2(reg, 3));
    if (REGTAINTVAL2(reg, 4) > 0) return IID2ID(REGTAINTVAL2(reg, 4));
    if (REGTAINTVAL2(reg, 5) > 0) return IID2ID(REGTAINTVAL2(reg, 5));
    if (REGTAINTVAL2(reg, 6) > 0) return IID2ID(REGTAINTVAL2(reg, 6));


    if (REGTAINTVAL1(reg, 0) > 0) return IID2ID(REGTAINTVAL1(reg, 0));
    if (REGTAINTVAL1(reg, 1) > 0) return IID2ID(REGTAINTVAL1(reg, 1));
    if (REGTAINTVAL1(reg, 2) > 0) return IID2ID(REGTAINTVAL1(reg, 2));
    if (REGTAINTVAL1(reg, 3) > 0) return IID2ID(REGTAINTVAL1(reg, 3));
    if (REGTAINTVAL1(reg, 4) > 0) return IID2ID(REGTAINTVAL1(reg, 4));
    if (REGTAINTVAL1(reg, 5) > 0) return IID2ID(REGTAINTVAL1(reg, 5));
    if (REGTAINTVAL1(reg, 6) > 0) return IID2ID(REGTAINTVAL1(reg, 6));
    if (REGTAINTVAL1(reg, 7) > 0) return IID2ID(REGTAINTVAL1(reg, 7));

    return -1;
  }

  if (size == 4)
  {
  	if (REGTAINTVAL4(reg, 0) > 0) return IID2ID(REGTAINTVAL4(reg, 0));

  	if (REGTAINTVAL2(reg, 0) > 0) return IID2ID(REGTAINTVAL2(reg, 0));
  	if (REGTAINTVAL2(reg, 1) > 0) return IID2ID(REGTAINTVAL2(reg, 1));
  	if (REGTAINTVAL2(reg, 2) > 0) return IID2ID(REGTAINTVAL2(reg, 2));


    if (REGTAINTVAL1(reg, 0) > 0) return IID2ID(REGTAINTVAL1(reg, 0));
    if (REGTAINTVAL1(reg, 1) > 0) return IID2ID(REGTAINTVAL1(reg, 1));
    if (REGTAINTVAL1(reg, 2) > 0) return IID2ID(REGTAINTVAL1(reg, 2));
    if (REGTAINTVAL1(reg, 3) > 0) return IID2ID(REGTAINTVAL1(reg, 3));

    return -1;
  }

  if (size == 2)
  {
  	if (REGTAINTVAL2(reg, 0) > 0) return IID2ID(REGTAINTVAL2(reg, 0));

  	if (REGTAINTVAL1(reg, 0) > 0) return IID2ID(REGTAINTVAL1(reg, 0));
  	if (REGTAINTVAL1(reg, 1) > 0) return IID2ID(REGTAINTVAL1(reg, 1));

  	return -1;
  }

  if (size == 1)
  {
  	if (REGTAINTVAL1(reg, 0) > 0) return IID2ID(REGTAINTVAL1(reg, 0));

  	return -1;
  }

  // should never come here.
  FAIL();

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

  LDUMP("Utils:\t\tFIXING SIZE: Created new id %d from uid %d size %d.\n", newid, ids_[newid].uid, REGSIZE(reg));

  for (int i = 0; i < REGSIZE(reg); i++)
  {
    int newiid = nshr_tid_new_iid(newid, i);

    if (i == 0)
    {
      LDUMP("Utils:\t\tCreated new iid %d for reg %s byte %d, to id %d size %d index %d\n", 
              newiid, REGNAME(reg), REGSTART(reg) + i, newid, ID2SIZE(newid), IID2INDEX(newiid));
    }

    SETREGTAINTVAL(reg, i, index, newiid);
  }

  return newid;
}

int nshr_tid_modify_id(int reg_index, enum prop_type operation, int64 value, int is_id)
{
  // will either return -1 (not tainted), same (size correct) or new id.
  int newid = nshr_reg_get_or_fix_sized_taint(reg_index);

  if (newid == -1)
  {
  	return -1;
  }

  newid = nshr_tid_copy_id(newid);

  /*
  Now append the new one. For some cases we can just
  modify the last operation to include the new one.
  */

  if (ID2OPSIZE(newid) > 0 &&                                                // we have at least 1 operation
        ID2OP(newid, ID2OPSIZE(newid) - 1).type == operation &&              // last operation is the same
          ID2OP(newid, ID2OPSIZE(newid) - 1).is_id == 0 &&                   // last operation is by constant 
              (operation == PROP_ADD || operation == PROP_SUB) &&            // operation is of specific type
                      is_id == 0)                                            // new operation is also by constant
  {
    if (operation == PROP_ADD)
    {
      ids_[newid].ops[ids_[newid].ops_size - 1].value += value;
    }
    else if (operation == PROP_SUB)
    {
      ids_[newid].ops[ids_[newid].ops_size - 1].value -= value;
    }
  }
  else
  {
    /*
    Just add a new operation.
    */
    ID2OP(newid, ID2OPSIZE(newid)).type  = operation;
    ID2OP(newid, ID2OPSIZE(newid)).is_id = is_id;
    ID2OP(newid, ID2OPSIZE(newid)).value = value;

    ID2OPSIZE(newid)++;
  }

  LDUMP("Utils:\t\tAppended operation '%s' to id %d by %d.\n", PROP_NAMES[operation], newid, value);

  return newid;
}

int nshr_tid_new_uid(int fd)
{
  uids_[nextUID].fd       = fd;

  int newid = nshr_tid_new_id();
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

int64_t mem_taint_get_addr(int index, uint64_t addr)
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