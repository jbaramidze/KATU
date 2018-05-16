#include "dr_api.h"
#include "drwrap.h"
#include "drmgr.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

#include "lp_lib.h"


void dump()
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
				dr_printf("\tOperation #%d: '%s' by %lld\n", j, PROP_NAMES[ids_[i].ops[j].type],
					ids_[i].ops[j].value);
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
      DIE("ERROR! drsym_exit failure.\n");
    }

    drmgr_exit();

    dump();

    dr_printf("Info:\t\tGenerated instr pointers: %d.\n", instr_next_pointer);

    for (int i = 0; i < instr_next_pointer; i++) 
    {
        // FIXME: we have a crash here sometimes.
    	instr_destroy(dr_get_current_drcontext(), instr_pointers[i]);
    }
}

static void nshr_handle_taint(long long addr, int size)
{
  nshr_taint(addr, size, 900);
}

static void nshr_handle_dump(long long addr)
{
    int index = mem_taint_find_index(addr, 0);

    int tained = MEMTAINTED(index, addr);

    if (tained == -1)
    {
    	dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#-1\n");

    	return;
    }

    int id = MEMTAINTVAL(index, addr);

	dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#%d, index %d.\n", 
		          addr, id, index);

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
      SETMEMTAINTVAL(i, j, -1);
      SETMEMTAINTADDR(i, j, 0);
    }
  }

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      taint_reg_.value[i][j] = -1;
    }
  }

  nshr_init_opcodes();

  eflags_.valid = -1;

  lp = make_lp(0, ILP_MAX_CONSTR);

  if (lp == NULL)
  {
  	DIE("ERROR! Failed making LP\n");
  }
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
    DIE("ERROR:! Failed starting drmgr.\n");
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
  dr_annotation_register_call("nshrtaint",
                                (void *) nshr_handle_taint, false, 2, DR_ANNOTATION_CALL_TYPE_FASTCALL);

  if (drsym_init(0) != DRSYM_SUCCESS) 
  {
    DIE("ERROR! Failed starting drsym.\n");
  }

  if (!drwrap_init())
  {	
    DIE("ERROR! Failed starting drwrap.\n");
  }

  init();

  dr_printf("Info:\t\tStarted!\n");
}
