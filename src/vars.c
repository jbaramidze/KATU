#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

int64_t			taint_[TAINTMAP_NUM][TAINTMAP_SIZE][2];
instrFunc		instrFunctions[MAX_OPCODE];
taint_t 		taintReg_[16][8];
Fd_entity 		fds_[MAX_FD];
bool 			started_ 						= 0;

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


// Create new taint id, scal1*id1 + id2 and return it's id
int nshr_addtid_scale_add(int scale, int id1, int id2)
{
  int i, j;

  for (i = 0; i < ids_[id1].size; i++)
  {
    ids_[nextID].coeff[i] = ids_[id1].coeff[i]*scale;
    ids_[nextID].uids[i]  = ids_[id1].uids[i];
  }

  for (j = 0; j < ids_[id2].size; j++)
  {
  	ids_[nextID].coeff[i + j] = ids_[id2].coeff[j];
  	ids_[nextID].uids[i + j]  = ids_[id2].uids[j];
  }

  ids_[nextID].offset = ids_[id1].offset + ids_[id2].offset;
  ids_[nextID].size = ids_[id1].size + ids_[id2].size;

  dr_printf("Engine:\t\tReturning new id %d size %d offset %d Sum of: ", 
  	            nextID, ids_[nextID].size, ids_[nextID].offset);

  for (i = 0; i < ids_[nextID].size; i++)
  {
  	dr_printf("%d*#%d ", ids_[nextID].coeff[i], ids_[nextID].uids[i]);
  }

  dr_printf("\n");

  nextID++;

  return nextID;
}
