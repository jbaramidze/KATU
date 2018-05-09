#include "dr_api.h"
#include "drsyms.h"
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
				dr_printf("\tOperation #%d: '%s' by %lld, ID_entity=%d\n", j, PROP_NAMES[ids_[i].ops[j].type],
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

    int id1 = MEMTAINTVAL1(index, addr);
    int id2 = MEMTAINTVAL2(index, addr);
    int id3 = MEMTAINTVAL4(index, addr);
    int id4 = MEMTAINTVAL8(index, addr);

	dr_printf("Helper:\t\tChecking taint for 0x%llx: TAINT#[%d, %d, %d, %d], index %d.\n", 
		          addr, id1, id2, id3, id4, index);

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
      SETMEMTAINTVAL(i, j, 0, -1);
      SETMEMTAINTVAL(i, j, 1, -1);
      SETMEMTAINTVAL(i, j, 2, -1);
      SETMEMTAINTVAL(i, j, 3, -1);

      SETMEMTAINTADDR(i, j, 0);
    }
  }

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      taint_reg_.value[i][j][0] = -1;
      taint_reg_.value[i][j][1] = -1;
      taint_reg_.value[i][j][2] = -1;
      taint_reg_.value[i][j][3] = -1;
    }
  }

  nshr_init_opcodes();

  eflags_.valid = -1;
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
    dr_annotation_register_call("nshrtaint",
                                (void *) nshr_handle_taint, false, 2, DR_ANNOTATION_CALL_TYPE_FASTCALL);

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



  lprec *lp;
  int Ncol, *colno = NULL, j, ret = 0;
  REAL *row = NULL;

  /* We will build the model row by row
     So we start with creating a model with 0 rows and 2 columns */
  Ncol = 2; /* there are two variables in the model */
  lp = make_lp(0, Ncol);
  if(lp == NULL)
    ret = 1; /* couldn't construct a new model... */

  if(ret == 0) {
    /* let us name our variables. Not required, but can be useful for debugging */
    set_col_name(lp, 1, "x");
    set_col_name(lp, 2, "y");

    /* create space large enough for one row */
    colno = (int *) malloc(Ncol * sizeof(*colno));
    row = (REAL *) malloc(Ncol * sizeof(*row));
    if((colno == NULL) || (row == NULL))
      ret = 2;
  }

  if(ret == 0) {
    set_add_rowmode(lp, TRUE);  /* makes building the model faster if it is done rows by row */

    /* construct first row (120 x + 210 y <= 15000) */
    j = 0;

    colno[j] = 1; /* first column */
    row[j++] = 120;

    colno[j] = 2; /* second column */
    row[j++] = 210;

    /* add the row to lpsolve */
    if(!add_constraintex(lp, j, row, colno, LE, 15000))
      ret = 3;
  }

  if(ret == 0) {
    /* construct second row (110 x + 30 y <= 4000) */
    j = 0;

    colno[j] = 1; /* first column */
    row[j++] = 110;

    colno[j] = 2; /* second column */
    row[j++] = 30;

    /* add the row to lpsolve */
    if(!add_constraintex(lp, j, row, colno, LE, 4000))
      ret = 3;
  }

  if(ret == 0) {
    /* construct third row (x + y <= 75) */
    j = 0;

    colno[j] = 1; /* first column */
    row[j++] = 1;

    colno[j] = 2; /* second column */
    row[j++] = 1;

    /* add the row to lpsolve */
    if(!add_constraintex(lp, j, row, colno, LE, 75))
      ret = 3;
  }

  if(ret == 0) {
    set_add_rowmode(lp, FALSE); /* rowmode should be turned off again when done building the model */

    /* set the objective function (143 x + 60 y) */
    j = 0;

    colno[j] = 1; /* first column */
    row[j++] = 143;

    colno[j] = 2; /* second column */
    row[j++] = 60;

    /* set the objective in lpsolve */
    if(!set_obj_fnex(lp, j, row, colno))
      ret = 4;
  }

  if(ret == 0) {
    /* set the object direction to maximize */
    set_maxim(lp);

    /* just out of curioucity, now show the model in lp format on screen */
    /* this only works if this is a console application. If not, use write_lp and a filename */
    write_LP(lp, stdout);
    /* write_lp(lp, "model.lp"); */

    /* I only want to see important messages on screen while solving */
    set_verbose(lp, IMPORTANT);

    /* Now let lpsolve calculate a solution */
    ret = solve(lp);
    if(ret == OPTIMAL)
      ret = 0;
    else
      ret = 5;
  }

  if(ret == 0) {
    /* a solution is calculated, now lets get some results */

    /* objective value */
    dr_printf("Objective value: %f\n", get_objective(lp));

    /* variable values */
    get_variables(lp, row);
    for(j = 0; j < Ncol; j++)
      dr_printf("%s: %f\n", get_col_name(lp, j + 1), row[j]);

    /* we are done now */
  }

  /* free allocated memory */
  if(row != NULL)
    free(row);
  if(colno != NULL)
    free(colno);

  if(lp != NULL) {
    /* clean up such that all used memory by lpsolve is freed */
    delete_lp(lp);
  }
}
