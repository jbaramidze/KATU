#undef LOGNORMAL
#undef LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"


//
// Return true for syscalls we want to monitor.
//

bool katu_syscall_filter(void *drcontext, int sysnum)
{
  if (sysnum == SYS_read || sysnum == SYS_open) 
  {
    return true;
  }

  return false;
}

char *open_path;

static void pre_open(void *drcontext)
{
  open_path = (char *) dr_syscall_get_param(drcontext, 0);
}

static void post_open(void *drcontext)
{
  int result = (int) dr_syscall_get_result(drcontext);

  // WARNING! actual syscall returns -1 to -4095 for errors.
  if (result < 0)
  {
    LTEST("Syscall:\tFailed opening %s.\n", open_path);
  }
  else
  {
    LTEST("Syscall:\tOpened %s as FD#%d.\n", open_path, result);

    fds_[result] = fds_history_index_++;

    if (fds_history_index_ >= MAX_FILE_HISTORY)
    {
      FAIL();
    }

    fds_history_[fds_[result]].secure = is_path_secure(open_path);
    fds_history_[fds_[result]].path = open_path;
  }
}

int   read_fd;
char *read_addr;

static void pre_read(void *drcontext)
{
  read_fd   =          dr_syscall_get_param(drcontext, 0);
  read_addr = (char *) dr_syscall_get_param(drcontext, 1);
}

static void post_read(void *drcontext)
{
  int result = (int)    dr_syscall_get_result(drcontext);

  // WARNING! actual syscall returns -1 to -4095 for errors.
  if (result < 0)
  {
    LTEST("Syscall:\tfailed reading from FD#%d.\n", read_fd);
  }
  else
  {
    LTEST("Syscall:\tRead %d bytes from FD#%d to %p\n", result, read_fd, read_addr);

    katu_taint_by_fd((reg_t) read_addr, result, fds_[read_fd]);
  }
}

//
// Called for each syscall.
//

bool katu_event_pre_syscall(void *drcontext, int id)
{
  STOP_IF_NOT_ACTIVE(true)

  if (id == SYS_read)
  {
    pre_read(drcontext);
  }
  else if (id == SYS_open)
  {
    pre_open(drcontext);
  }

  return true;
}

void katu_event_post_syscall(void *drcontext, int id)
{
  STOP_IF_NOT_ACTIVE()

  if (id == SYS_read)
  {
    post_read(drcontext);
  }
  else if (id == SYS_open)
  {
    post_open(drcontext);
  }

  return;
}
