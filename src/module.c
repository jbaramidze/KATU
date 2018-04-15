#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"



static void
event_exit(void)
{
    dr_printf("Info:\t\tExit.\n");
}


//
// Called from executable via dynamorio_annotate_zhani_signal(i).
// Marks where to begin/end instrumentation. temporary.
//

static void nshr_handle_annotation(int index)
{
  if (index == 1)
  {
    started_ = 1;
  }
  else
  {
    started_ = 0;
  }
}


void init(void)
{

  for (int i = 0; i < MAX_FD; i++)
  {
    fds_[i].used = false;
  }

  for (int i = 0; i < TAINTMAP_NUM; i++)
  {
    for (int j = 0; j < TAINTMAP_SIZE; j++)
    {
      taint_[i][j][0] = 0;
      taint_[i][j][1] = -1;
    }
  }

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      taintReg_[i][j] = -1;
    }
  }

  nshr_init_opcodes();
}

DR_EXPORT void
dr_init(client_id_t client_id)
{
    dr_set_client_name("Nashromi",
                       "jbaramidze@gmail.com");

    dr_register_bb_event(nshr_event_bb);
    dr_register_filter_syscall_event(nshr_syscall_filter);
//    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(nshr_event_post_syscall);
    dr_register_exit_event(event_exit);
    disassemble_set_syntax(DR_DISASM_INTEL);
    dr_annotation_register_call("dynamorio_annotate_zhani_signal",
                                (void *) nshr_handle_annotation, false, 1, DR_ANNOTATION_CALL_TYPE_FASTCALL);

    init();
    dr_printf("Info:\t\tStarted!\n");
}
