#define LOGTEST
#define LOGDEBUG
#define LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

int64_t			taint_[TAINTMAP_NUM][TAINTMAP_SIZE][2];
instrFunc		instrFunctions[MAX_OPCODE];
taint_t 		taintReg_[16][8];
Fd_entity 		fds_[MAX_FD];
enum mode 		started_ 						= MODE_IGNORING;

UID_entity		uids_[MAX_UID];
ID_entity		ids_[MAX_ID];

// Used to describe true taint sources (e.g. read())
int				nextUID							= 1;

// Used to describe memory area
int 			nextID							= 1;


void assert(bool a)
{
  if (a == false)
  {
  	dr_printf("ASSERT FAILED!!!\n");
  	exit(1);
  }
}


int changeID(int id, enum prop_type operation, int64 value, int is_id)
{
  /*
  First copy everything from old id.
  */
  ids_[nextID].uid      = ids_[id].uid;
  ids_[nextID].ops_size = ids_[id].ops_size;
  ids_[nextID].size     = ids_[id].size;
  ids_[nextID].index    = ids_[id].index;

  int i;

  for (i = 0; i < ids_[id].ops_size; i++)
  {
    ids_[nextID].ops[i].type  = ids_[id].ops[i].type;
    ids_[nextID].ops[i].value = ids_[id].ops[i].value;
    ids_[nextID].ops[i].is_id = ids_[id].ops[i].is_id;
  }

  /*
  Now append the new one. For some cases we can just
  modify the last operation to include the new one.
  */

  if (ids_[nextID].ops_size > 0 &&                                            // we have at least 1 operation
          ids_[nextID].ops[ids_[nextID].ops_size - 1].type == operation &&    // last operation is the same
              (operation == PROP_ADD || operation == PROP_SUB) &&             // operation is of specific type
                  ids_[nextID].ops[ids_[nextID].ops_size - 1].is_id == 0  &&  // last operation is by constant 
                      is_id == 0)                                              // new operation is also by constant
  {
    if (operation == PROP_ADD)
    {
      ids_[nextID].ops[ids_[nextID].ops_size - 1].value += value;
    }
    else if (operation == PROP_SUB)
    {
      ids_[nextID].ops[ids_[nextID].ops_size - 1].value -= value;
    }
  }
  else
  {
    /*
    Just add a new operation.
    */
    ids_[nextID].ops[ids_[nextID].ops_size].type  = operation;
    ids_[nextID].ops[ids_[nextID].ops_size].is_id = is_id;
    ids_[nextID].ops[ids_[nextID].ops_size].value = value;

    ids_[nextID].ops_size++;
  }

  return nextID++;
}

int newUID(int fd)
{
  uids_[nextUID++].fd       = fd;

  ids_[nextID].uid          = nextUID;
  ids_[nextID].ops_size     = 0;
  ids_[nextID].size         = 1;
  ids_[nextID].index        = 0;

  return nextID++;
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