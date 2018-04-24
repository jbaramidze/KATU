#define LOGTEST
#define LOGDEBUG
#define LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

int64_t			taint_[TAINTMAP_NUM][TAINTMAP_SIZE][2];
instrFunc		instrFunctions[MAX_OPCODE];
int64_t 		taintReg_[16][8];
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


int nshr_tid_new_id()
{
  return nextID++;
}

int nshr_tid_new_iid(int id, int size, int index)
{
  iids_[nextIID].id    = id;
  iids_[nextIID].size  = size;
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

  /*
  First copy everything from old id.
  */

  ids_[newid].uid      = ids_[id].uid;
  ids_[newid].ops_size = ids_[id].ops_size;

  int i;

  for (i = 0; i < ids_[id].ops_size; i++)
  {
    ids_[newid].ops[i].type  = ids_[id].ops[i].type;
    ids_[newid].ops[i].value = ids_[id].ops[i].value;
    ids_[newid].ops[i].is_id = ids_[id].ops[i].is_id;
  }

  return newid;
}


int nshr_reg_fix_size(int index_reg)
{
  int tainted = 0;
  int uid     = -1;

  for (int i = 0; i < REGSIZE(index_reg); i++)
  {
    if (REGTAINT(index_reg, i) > 0)
    {
      tainted = 1;

      uid = ids_[REGTAINTID(index_reg, i)].uid;
    }
  }

  if (tainted == 0) return -1;
 
  /*
  FIXME: Make sure no constraints were applied before we change the size.
         If there are some constratins, things get too complicated -> FAIL();
  */

  // Make new taint.

  int newid = nshr_tid_new_id();

  ids_[newid].uid      = uid;
  ids_[newid].ops_size = 0;

  for (int i = 0; i < REGSIZE(index_reg); i++)
  {
    int newiid = nshr_tid_new_iid(newid, REGSIZE(index_reg), i);

    REGTAINT(index_reg, i) = newiid;
  }
}

int nshr_tid_change_id(int id, enum prop_type operation, int64 value, int is_id)
{
  int newid = nshr_tid_copy_id(id);

  /*
  Now append the new one. For some cases we can just
  modify the last operation to include the new one.
  */

  if (ids_[newid].ops_size > 0 &&                                            // we have at least 1 operation
          ids_[newid].ops[ids_[newid].ops_size - 1].type == operation &&     // last operation is the same
              (operation == PROP_ADD || operation == PROP_SUB) &&            // operation is of specific type
                  ids_[newid].ops[ids_[newid].ops_size - 1].is_id == 0  &&   // last operation is by constant 
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
    ids_[newid].ops[ids_[newid].ops_size].type  = operation;
    ids_[newid].ops[ids_[newid].ops_size].is_id = is_id;
    ids_[newid].ops[ids_[newid].ops_size].value = value;

    ids_[newid].ops_size++;
  }

  return newid;
}

int nshr_tid_new_uid(int fd)
{
  uids_[nextUID].fd       = fd;

  int newid = nshr_tid_new_id();
  int newiid = nshr_tid_new_iid(newid, 1, 0);


  ids_[newid].uid          = nextUID;
  ids_[newid].ops_size     = 0;

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