#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "nashromi.h"




static REAL KS[] = {1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1,
                    1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1};

// Used by recursively_get_uids, for objective function.

static int uids_objective_map[MAX_UID];
static int uids_objective_vector[MAX_UID];
static int uids_objective_vector_size;

// Used by recursively_get_uids, for constraints.

static int uids_constr_map[MAX_UID];
static int uids_constr_vector[MAX_UID];
static int uids_constr_vector_size;

// Used by to keep info about all the uids that matter.

static int uids_total_map[MAX_UID];
static int uids_total_vector[MAX_UID];
static int uids_total_vector_size;

// Temporary one used to pass to ilp_*

static int uids_t[MAX_UID];

// We need it to map uid's to integers.
// Will use uids_total_map.

static int uids_counter;
static int uids_total[MAX_UID];


void ilp_bound(int *input, int size, int type)
{
  if (size > 256) 
  {
    FAIL();
  }

  int coeff[512];

  for (int i = 0; i < size; i++)
  {
    coeff[2*i]   = 2*input[i];
    coeff[2*i+1] = 2*input[i] + 1;
  }

  if(!add_constraintex(lp, 2*size, KS, coeff, type, 0))
  {
    FAIL();
  }
}

void ilp_objective(int *input, int size)
{
  if (size > 256) 
  {
    FAIL();
  }

  int coeff[512];

  for (int i = 0; i < size; i++)
  {
    coeff[2*i]   = 2*input[i];
    coeff[2*i+1] = 2*input[i] + 1;
  }

  if(!set_obj_fnex(lp, 2*size, KS, coeff))
  {
    FAIL();
  }
}


static void recursively_get_uids_objective(int id)
{
  if (uids_objective_map[ID2UID(id)] == -1)
  {
    uids_objective_vector[uids_objective_vector_size++] = ID2UID(id);
    uids_objective_map[ID2UID(id)] = uids_counter;

    uids_total[uids_counter++] = ID2UID(id);
  }

  for (int i = 0; i < ID2OPSIZE(id); i++)
  {
    recursively_get_uids_objective(ID2OP(id, i).value);
  }
}

static void recursively_get_uids_constr(int id)
{
  if (uids_constr_map[ID2UID(id)] == -1)
  {
    uids_constr_vector[uids_constr_vector_size++] = ID2UID(id);
    uids_constr_map[ID2UID(id)] = 1;
  }

  // Add in global ones as well, since we need to find it's constraints as well.
  if (uids_total_map[ID2UID(id)] == -1)
  {
    uids_total_vector[uids_total_vector_size++] = ID2UID(id);
    uids_total_map[ID2UID(id)] = uids_counter;

    uids_total[uids_counter++] = ID2UID(id);
  }

  for (int i = 0; i < ID2OPSIZE(id); i++)
  {
    recursively_get_uids_constr(ID2OP(id, i).value);
  }
}

int solve_ilp(int id DBG_END_TAINTING_FUNC)
{
  LDEBUG("ILP:\tStarting ILP for ID#%d.\n", id);

  uids_counter = 1;

  /*
  Get uids paticipating in this id.
  */

  for(int i = 0; i < MAX_UID; i++) 
  	       uids_objective_map[i] = -1;
  uids_objective_vector_size = 0;

  recursively_get_uids_objective(id);

  uids_total_vector_size = uids_objective_vector_size;

  for (int i = 0; i < MAX_UID; i++)
  {
  	uids_total_map[i]    = uids_objective_map[i];
  	uids_total_vector[i] = uids_objective_vector[i];
  }

  LDUMP("ILP:\tPrinting objective: \n");

  for (int i = 0; i < uids_objective_vector_size; i++) 
  {
    LDUMP("%d (%d)  ", uids_objective_vector[i], uids_total_map[uids_objective_vector[i]]);
  }

  LDUMP("\n");

  for (int i = 0; i < uids_objective_vector_size; i++) uids_t[i] = uids_total_map[uids_objective_vector[i]];

  set_add_rowmode(lp, FALSE);

  ilp_objective(uids_t, uids_objective_vector_size);

  /*
  For each uid, get constraint lists,
  while adding new uids as we proceed
  */

  while (uids_total_vector_size > 0)
  {
  	int curr_uid = uids_total_vector[--uids_total_vector_size];

  	Group_restriction *gr = uids_[curr_uid].gr;

    while (gr != NULL)
    {
  	  // Add this gr as a constraint.
  	  int constrained_id = gr -> id;

      for(int i = 0; i < MAX_UID; i++) 
  	          uids_constr_map[i] = -1;
      uids_constr_vector_size = 0;

      recursively_get_uids_constr(constrained_id);

      LDUMP("ILP:\tPrinting constraint: \n");

      for (int i = 0; i < uids_constr_vector_size; i++) 
      {
        LDUMP("%d (%d)  ", uids_constr_vector[i], uids_total_map[uids_constr_vector[i]]);
      }

      LDUMP("[%d]\n", gr -> bound_type);

      set_add_rowmode(lp, TRUE);

      for (int i = 0; i < uids_constr_vector_size; i++) uids_t[i] = uids_total_map[uids_constr_vector[i]];

      if (gr -> bound_type & TAINT_BOUND_LOW)
      {
        ilp_bound(uids_t, uids_constr_vector_size, LE);
      }
      if (gr -> bound_type & TAINT_BOUND_HIGH)
      {
        ilp_bound(uids_t, uids_constr_vector_size, GE);
      }
      if (gr -> bound_type & TAINT_BOUND_FIX)
      {
        ilp_bound(uids_t, uids_constr_vector_size, LE);
        ilp_bound(uids_t, uids_constr_vector_size, GE);
      }

  	  gr = gr -> next;
  	}
  }

  LDUMP("ILP:\tPrinting total: \n");

  for (int i = 1; i < uids_counter; i++) 
  {
  	LDUMP("%d (%d)  ", uids_total[i], uids_total_map[uids_total[i]]);
  }

  LDUMP("\n");

  int unbound = 0;

  set_add_rowmode(lp, FALSE);
  
  set_maxim(lp);

  #ifdef DEBUG
  write_LP(lp, stdout);
  set_verbose(lp, IMPORTANT);
  #else
  set_verbose(lp, CRITICAL);
  #endif 

  solve(lp);

  LDEBUG("ILP:\tObjective value MAX: %f\n\n", get_objective(lp));

  if (get_objective(lp) > 10 || get_objective(lp) < -10)
  {
  	unbound = 1;
  }

  set_minim(lp);

  #ifdef DEBUG
  write_LP(lp, stdout);
  set_verbose(lp, IMPORTANT);
  #else
  set_verbose(lp, CRITICAL);
  #endif

  solve(lp);

  LDEBUG("ILP:\tObjective value MIN: %f\n\n", get_objective(lp));

  if (get_objective(lp) > 10 || get_objective(lp) < -10)
  {
  	unbound = 1;
  }

  while (get_Nrows(lp) > 0)
  {
    del_constraint(lp, 1);
  }

  if (unbound == 0)
  {
  	return 1;
  }
  else
  {
    #ifdef DBG_PASS_INSTR
    drsym_info_t *func = get_func(instr_get_app_pc(instr));
    LWARNING("!!!WARNING!!! ILP Detected unbounded access for ID#%d (UID#%d), at %s  %s:%d\n", 
    	               id, ID2UID(id), func -> name, func -> file, func -> line);
    #else
    LWARNING("!!!WARNING!!! ILP Detected unbounded access for ID#%d (UID#%d)\n", id, ID2UID(id));
    #endif

  	return 0;
  }
}