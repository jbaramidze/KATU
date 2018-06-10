#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "nashromi.h"

static REAL KS[2048];

// Used by recursively_get_uids, for objective function.

static int uids_objective_map[MAX_UID];
static int uids_objective_vector[MAX_UID][2];
static int uids_objective_vector_size;

// Used by recursively_get_uids, for constraints.

static int uids_constr_map[MAX_UID];
static int uids_constr_vector[MAX_UID][2];
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

void reset_KS()
{
  int t = 1;

  for (int i = 0; i < 2048; i++)
  {
    KS[i] = t;
    t *= -1;
  }

  return;
}

void ilp_bound(int *input, int size, int type)
{
  if (size > 1024) 
  {
    DIE("ERROR! ILP Failure at [A]\n");
  }

  int coeff[2048];

  for (int i = 0; i < size; i++)
  {
    coeff[2*i]   = 2*input[i];
    coeff[2*i+1] = 2*input[i] + 1;
  }

  if(!add_constraintex(lp, 2*size, KS, coeff, type, 0))
  {
    DIE("ERROR! ILP Failure at [B]\n");
  }
}

void ilp_objective(int *input, int size)
{
  if (size > 1024) 
  {
    DIE("ERROR! ILP Failure at [C]\n");
  }

  int coeff[2048];

  for (int i = 0; i < size; i++)
  {
    coeff[2*i]   = 2*input[i];
    coeff[2*i+1] = 2*input[i] + 1;
  }

  if(!set_obj_fnex(lp, 2*size, KS, coeff))
  {
    DIE("ERROR! ILP Failure at [D]\n");
  }
}


static void recursively_get_uids_objective(int id, int type)
{
  int id_began_at = uids_objective_vector_size;

  if (uids_objective_map[ID2UID(id)] == -1)
  {
    uids_objective_vector[uids_objective_vector_size][0] = ID2UID(id);

    if (type == PROP_ADD)
    {
      uids_objective_vector[uids_objective_vector_size][1] = 1;
    }
    else if (type == PROP_SUB)
    {
      uids_objective_vector[uids_objective_vector_size][1] = -1;
    }

    uids_objective_vector_size++;

    uids_objective_map[ID2UID(id)] = uids_counter;

    uids_total[uids_counter++] = ID2UID(id);
  }

  for (int i = 0; i < ID2OPSIZE(id); i++)
  {
    if (ID2OP(id, i).type == PROP_NEG)
    {
      for (int i = 2*id_began_at; i < 2*uids_objective_vector_size; i++)
      {
        KS[i] *= -1;
      }
    }
    else
    {
      recursively_get_uids_objective(ID2OP(id, i).value, ID2OP(id, i).type);
    }
  }
}

static void recursively_get_uids_constr(int id, int type)
{
  int id_began_at = uids_constr_vector_size;

  if (uids_constr_map[ID2UID(id)] == -1)
  {
    uids_constr_vector[uids_constr_vector_size][0] = ID2UID(id);

    if (type == PROP_ADD)
    {
      uids_constr_vector[uids_constr_vector_size][1] = 1;
    }
    else if (type == PROP_SUB)
    {
      uids_constr_vector[uids_constr_vector_size][1] = -1;
    }
    else
    {
      FAIL();
    }

    uids_constr_vector_size++;

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
    if (ID2OP(id, i).type == PROP_NEG)
    {
      for (int i = 2*id_began_at; i < 2*uids_constr_vector_size; i++)
      {
        KS[i] *= -1;
      }
    }
    else
    {
      recursively_get_uids_constr(ID2OP(id, i).value, ID2OP(id, i).type);
    }
  }
}

int solve_ilp_for_id(int id DBG_END_TAINTING_FUNC)
{
  LDEBUG("ILP:\tStarting ILP for ID#%d.\n", id);

  uids_counter = 1;

  reset_KS();

  /*
  Get uids paticipating in this id.
  */

  for(int i = 0; i < MAX_UID; i++) 
           uids_objective_map[i] = -1;
  uids_objective_vector_size = 0;

  recursively_get_uids_objective(id, PROP_ADD);

  uids_total_vector_size = uids_objective_vector_size;

  for (int i = 0; i < MAX_UID; i++)
  {
    uids_total_map[i]    = uids_objective_map[i];
    uids_total_vector[i] = uids_objective_vector[i][0];
  }

  LDUMP("ILP:\tPrinting objective: \n");

  for (int i = 0; i < uids_objective_vector_size; i++) 
  {
    LDUMP("%d*%d (%d)  ", uids_objective_vector[i][1], uids_objective_vector[i][0], 
                                uids_total_map[uids_objective_vector[i][0]]);
  }

  LDUMP("\n");

  for (int i = 0; i < uids_objective_vector_size; i++) 
  {
      uids_t[i] = uids_total_map[uids_objective_vector[i][0]];

      if (uids_objective_vector[i][1] == -1)
      {
        KS[2*i]*= -1;
        KS[2*i + 1]*= -1;
      }
  }

  set_add_rowmode(lp, FALSE);

  ilp_objective(uids_t, uids_objective_vector_size);

  reset_KS();

  /*
  For each uid, get constraint lists,
  while adding new uids as we proceed
  */

  while (uids_total_vector_size > 0)
  {
    int curr_uid = uids_total_vector[--uids_total_vector_size];

    // Before moving on to group restrictions, add direct ones.
    if (uids_[curr_uid].bounded & TAINT_BOUND_LOW)
    {
      ilp_bound(&uids_total_map[curr_uid], 1, LE);
    }

    if (uids_[curr_uid].bounded & TAINT_BOUND_HIGH)
    {
      ilp_bound(&uids_total_map[curr_uid], 1, GE);
    }

    if (uids_[curr_uid].bounded & TAINT_BOUND_FIX)
    {
      ilp_bound(&uids_total_map[curr_uid], 1, EQ);
    }   

    Group_restriction *gr = uids_[curr_uid].gr;

    while (gr != NULL)
    {
      // Add this gr as a constraint.
      int constrained_id = gr -> id;

      for(int i = 0; i < MAX_UID; i++) 
              uids_constr_map[i] = -1;
      uids_constr_vector_size = 0;

      recursively_get_uids_constr(constrained_id, PROP_ADD);

      LDUMP("ILP:\tPrinting constraint: \n");

      for (int i = 0; i < uids_constr_vector_size; i++) 
      {
        LDUMP("%d*%d (%d)  ", uids_constr_vector[i][1], uids_constr_vector[i][0], 
                                 uids_total_map[uids_constr_vector[i][0]]);
      }

      LDUMP("[%d]\n", gr -> bound_type);

      set_add_rowmode(lp, TRUE);

      for (int i = 0; i < uids_constr_vector_size; i++) 
      {
        uids_t[i] = uids_total_map[uids_constr_vector[i][0]];

        if (uids_constr_vector[i][1] == -1)
        {
          KS[2*i]*= -1;
          KS[2*i + 1]*= -1;
        }
      }

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

      reset_KS();

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
  write_LP(lp, logfile_stream);
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
  write_LP(lp, logfile_stream);
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
    return 0;
  }
}

int solve_ilp(int *ids DBG_END_TAINTING_FUNC)
{
  int vulnerables = 0;

  for (int i = 0; i < 8; i++)
  {
    int id = ids[i];

    if (id == -1)
    {
      continue;
    }

    int r = solve_ilp_for_id(id DGB_END_CALL_ARG);

    if (r == 0)
    {
      vulnerables++;
    }
  }

  if (vulnerables >= MIN_VULNERABILITIES)
  {
    return -1;
  }

  return 1;
}