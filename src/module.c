#include "dr_api.h"
#include "drwrap.h"
#include "drmgr.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

#include "lp_lib.h"


void dump()
{
  dr_fprintf(dumpfile, "\n\nStarting dump of ID:\n");

  for (int i = 1; i < nshr_tid_new_id_get(); i++)
  {
    dr_fprintf(dumpfile, "ID #%d\t\t -> uid %d size %d ops_size: %d\n", i, ids_[i].uid, ids_[i].size, ids_[i].ops_size);

    if (ids_[i].ops_size > 0)
    {
      dr_fprintf(dumpfile, "\tOperations:\n");
      if (ids_[i].ops_size > DEFAULT_OPERATIONS)
      {
        FAIL();
      }

      for (int j = 0; j < ids_[i].ops_size; j++)
      {
        dr_fprintf(dumpfile, "\tOperation #%d: '%s' by %lld\n", j, PROP_NAMES[ids_[i].ops[j].type],
          ids_[i].ops[j].value);
      }
    }
  }


  dr_fprintf(dumpfile, "\n\nStarting dump of UID:\n");

  for (int i = 1; i < nshr_tid_new_uid_get(); i++)
  {
    const char *path;

    if (uids_[i].descr_type == 0)
    {
      path = fds_history_[uids_[i].descriptor.fd].path;
    }
    else
    {
      path = files_history_[uids_[i].descriptor.file].path;
    }

    dr_fprintf(dumpfile, "UID #%d\t\t -> path %s bounded %d\n", i, path, uids_[i].bounded);

    Group_restriction *gr = uids_[i].gr;

    while(gr != NULL)
    {
      dr_fprintf(dumpfile, "\tGroup restriction id %d type %d.\n", gr -> id, gr -> bound_type);
      gr = gr -> next;
    }
  }
}

static void
event_exit(void)
{
    dr_printf("Info:\t\tStartint to exit.\n");

    //drwrap_exit();

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

    hashtable_delete(&func_hashtable);
    hashtable_delete(&FILEs_);

    for (int i = 1; i < nshr_tid_new_uid_get(); i++)
    {
      Group_restriction *gr = uids_[i].gr;

      while(gr != NULL)
      {
        Group_restriction *next = gr -> next;

        free(gr);

        gr = next;
      }
  }

  dr_close_file(logfile);
  dr_close_file(dumpfile);

  dr_printf("Info:\t\tExitting.\n");
}

static void nshr_handle_taint(long long addr, int size)
{
  nshr_taint_by_fd(addr, size, FD_MANUAL_TAINT);
}

static void nshr_handle_dump(long long addr)
{
  int index = mem_taint_find_index(addr, 0);

  int tained = MEMTAINTED(index, addr);

  if (tained == -1)
  {
    dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#-1\n", addr);

    return;
  }

  int id = MEMTAINTVAL(index, addr);

  dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#%d, index %d.\n", addr, id, index);
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
  set_outputstream(lp, logfile_stream);

  if (lp == NULL)
  {
    DIE("ERROR! Failed making LP\n");
  }

  hashtable_init_ex(&func_hashtable, HASH_BITS, HASH_INTPTR, false, true, hashtable_del_entry, NULL, NULL);
  hashtable_init_ex(&FILEs_,         4,         HASH_INTPTR, false, true, hashtable_del_entry, NULL, NULL);

  module_data_t *main_module = dr_get_main_module();

  main_address = (app_pc) dr_get_proc_address(main_module -> handle, "main");

  if (main_address == NULL)
  {
    dr_printf("ERROR! Failed getting address for main!!!!.\n");

    FAIL();
  }

  dr_free_module_data(main_module);

  // Initialize stdin/stdout/stderr
  fds_[0] = fds_history_index_++;
  fds_[1] = fds_history_index_++;
  fds_[2] = fds_history_index_++;

  fds_history_[fds_[0]].path = "<stdin>";
  fds_history_[fds_[1]].path = "<stdout>";
  fds_history_[fds_[2]].path = "<stderr>";

  fds_history_[fds_[0]].secure = 0;
  fds_history_[fds_[1]].secure = 0;
  fds_history_[fds_[2]].secure = 0;

  fds_history_[FD_MANUAL_TAINT].path   = cmd_arg_taint_path;
  fds_history_[FD_MANUAL_TAINT].secure = 0;
  fds_history_[FD_CMD_ARG].path        = cmd_arg_taint_path;
  fds_history_[FD_CMD_ARG].secure      = 0;

}

DR_EXPORT void
dr_init(client_id_t client_id)
{
  char *bound = getenv("LD_BIND_NOW");

  if (bound == NULL || *bound != '1')
  {
    dr_printf("ERROR: Please set LD_BIND_NOW variable before launching the tool.\n");

    exit(-1);
  }


  if (!drmgr_init())
  {
    DIE("ERROR:! Failed starting drmgr.\n");
  }

  dr_set_client_name("Nashromi",
                     "jbaramidze@gmail.com");

  disassemble_set_syntax(DR_DISASM_INTEL);

  drmgr_priority_t pri_replace = {sizeof(pri_replace), "nashromi", NULL, NULL, 800};

  drmgr_register_bb_instrumentation_event(NULL, nshr_event_bb, &pri_replace);
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

  /*if (!drwrap_init())
  {  
    DIE("ERROR! Failed starting drwrap.\n");
  }*/

  logfile  = dr_open_file(NSHR_LOGFILE_PATH, DR_FILE_WRITE_OVERWRITE);
  dumpfile = dr_open_file(NSHR_DUMPFILE_PATH, DR_FILE_WRITE_OVERWRITE);

  if (logfile == INVALID_FILE || dumpfile == INVALID_FILE) 
  {
    DIE("ERROR:! Failed opening log files.\n");
  }

  logfile_stream = fdopen(logfile, "w+");

  init();

  dr_printf("Info:\t\tStarted!\n");
}
