#define DUMP_SYSCALL

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"


//
// Return true for syscalls we want to monitor.
//

bool nshr_syscall_filter(void *drcontext, int sysnum)
{
  if (sysnum == SYS_read || sysnum == SYS_open) 
  {
    return true;
  }

  return false;
}

static void process_open(void *drcontext)
{
  char *path = (char *) dr_syscall_get_param(drcontext, 0);

  int result = (int) dr_syscall_get_result(drcontext);

  // WARNING! actual syscall returns -1 to -4095 for errors.
  if (result < 0)
  {
    LSYSCALL("Syscall:\tFailed opening %s.\n", path);
  }
  else
  {
    LSYSCALL("Syscall:\tOpened %s as FD#%d.\n", path, result);

    fds_[result].used = true;
    fds_[result].path = path;
  }
}

static void process_read(void *drcontext)
{
  int fd     = 			dr_syscall_get_param(drcontext, 0);
  char *addr = (char *) dr_syscall_get_param(drcontext, 1);
  int size   = 			dr_syscall_get_param(drcontext, 2);
  int result = (int)    dr_syscall_get_result(drcontext);

  UNUSED(fd);
  UNUSED(size);

  // WARNING! actual syscall returns -1 to -4095 for errors.
  if (result < 0)
  {
    LSYSCALL("Syscall:\tfailed reading from FD#%d.\n", fd);
  }
  else
  {
    LSYSCALL("Syscall:\tRead %d bytes from FD#%d to %p\n", result, fd, addr);

    nshr_taint((reg_t) addr, result, fd);
  }
}

//
// Called for each syscall.
//

void nshr_event_post_syscall(void *drcontext, int id)
{
  STOP_IF_NOT_STARTED()

  if (id == SYS_read)
  {
    process_read(drcontext);
  }
  else if (id == SYS_open)
  {
    process_open(drcontext);
  }

  return;
}
