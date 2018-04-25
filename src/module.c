#include "dr_api.h"
#include "drsyms.h"
#include "drwrap.h"
#include "drmgr.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"


static void dump()
{
	dr_printf("\n\nStarting dump of IID:\n");

	for (int i = 0; i < nshr_tid_new_iid_get(); i++)
	{
		dr_printf("IID #%d\t\t -> id %d index %d\n", i, iids_[i].id, iids_[i].index);
	}


	dr_printf("\n\nStarting dump of IID:\n");

	for (int i = 0; i < nshr_tid_new_id_get(); i++)
	{
		dr_printf("ID #%d\t\t -> uid %d size %d ops_size: %d\n", i, ids_[i].uid, ids_[i].size, ids_[i].ops_size);

		if (ids_[i].ops_size > 0)
		{
			dr_printf("\tOperations:\n");
			for (int j = 0; j < ids_[i].ops_size; j++)
			{
				dr_printf("\tOperation #%d: '%s' by %lld, is_id=%d\n", j, PROP_NAMES[ids_[i].ops[j].type],
					ids_[i].ops[j].value, ids_[i].ops[j].is_id);
			}
		}
	}
}

static void
event_exit(void)
{
    dr_printf("Info:\t\tExit.\n");

    drwrap_exit();

    if (drsym_exit() != DRSYM_SUCCESS)
    {
      FAIL();
    }

    drmgr_exit();

    dump();

}

static void nshr_handle_dump(long long addr)
{
    int index = find_index(addr, 0);
    int iid = MEMTAINTVAL(index, addr);
    if (iid == -1)
    {
    	dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#-1\n");

    	return;
    }

    int id = IIDTOID(iid);

	dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#%d, index %d.\n", 
		          addr, iid, index);

}


//
// Called from executable via dynamorio_annotate_zhani_signal(i).
// Marks where to begin/end instrumentation. temporary.
//

static void nshr_handle_annotation(int index)
{
  if (index == 1)
  {
    started_ = MODE_ACTIVE;
  }
  else
  {
    started_ = MODE_IGNORING;
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

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
   const char *module = dr_module_preferred_name(mod);

   dr_printf("Info:\t\tLoading %s.\n", module);

   if (strncmp(dr_module_preferred_name(mod), "libc.so", 7) == 0)
   {
     app_pc scanf_addr = (app_pc) dr_get_proc_address(mod -> handle, "scanf");

     dr_printf("Info:\t\tfound 'scanf' at %llx.\n", scanf_addr);

     //drwrap_wrap(scanf_addr, nshr_pre_scanf, nshr_post_scanf);
   }
}

DR_EXPORT void
dr_init(client_id_t client_id)
{
    if (!drmgr_init())
    {
      dr_printf("Info:\t\tERROR:\t\tFailed starting drmgr.\n");

      FAIL();
    }

    dr_set_client_name("Nashromi",
                       "jbaramidze@gmail.com");

    disassemble_set_syntax(DR_DISASM_INTEL);

    drmgr_register_bb_instrumentation_event(NULL, nshr_event_bb, NULL);
    drmgr_register_module_load_event(module_load_event);
    drmgr_register_post_syscall_event(nshr_event_post_syscall);
    drmgr_register_pre_syscall_event(nshr_event_pre_syscall);

    dr_register_filter_syscall_event(nshr_syscall_filter);
    dr_register_exit_event(event_exit);
    dr_annotation_register_call("dynamorio_annotate_zhani_signal",
                                (void *) nshr_handle_annotation, false, 1, DR_ANNOTATION_CALL_TYPE_FASTCALL);
    dr_annotation_register_call("nshr_dump_taint",
                                (void *) nshr_handle_dump, false, 1, DR_ANNOTATION_CALL_TYPE_FASTCALL);

    if (drsym_init(0) != DRSYM_SUCCESS) 
    {
      dr_printf("Info:\t\tERROR:\t\tFailed starting drsym.\n");

      FAIL();
    }

    if (!drwrap_init())
    {	
      dr_printf("Info:\t\tERROR:\t\tFailed starting drwrap.\n");

      FAIL();
    }

    init();

    dr_printf("Info:\t\tStarted!\n");
}
