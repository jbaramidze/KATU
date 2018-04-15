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

  for (i = 0; i < ids_[id1].LSsize; i++)
  {
    ids_[nextID].LScoeff[i] = ids_[id1].LScoeff[i]*scale;
    ids_[nextID].LSuids[i]  = ids_[id1].LSuids[i];
  }

  for (j = 0; j < ids_[id2].LSsize; j++)
  {
  	ids_[nextID].LScoeff[i + j] = ids_[id2].LScoeff[j];
  	ids_[nextID].LSuids[i + j]  = ids_[id2].LSuids[j];
  }

  ids_[nextID].LSoffset = ids_[id1].LSoffset + ids_[id2].LSoffset;
  ids_[nextID].LSsize = ids_[id1].LSsize + ids_[id2].LSsize;

  dr_printf("Engine:\t\tReturning new id %d size %d offset %d Sum of: ", 
  	            nextID, ids_[nextID].LSsize, ids_[nextID].LSoffset);

  for (i = 0; i < ids_[nextID].LSsize; i++)
  {
  	dr_printf("%d*#%d ", ids_[nextID].LScoeff[i], ids_[nextID].LSuids[i]);
  }

  dr_printf("\n");

  nextID++;

  return nextID;
}
