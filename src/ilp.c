#undef LOGWARNING
#undef LOGNORMAL
#undef LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "nashromi.h"

static REAL KS[2048];

#define MAX_CONSTRAINTS 1000

// Used by recursively_get_uids, for objective function.

static int *uid_objective_map;
static int uid_objective_vector[MAX_CONSTRAINTS][2];
static int uid_objective_vector_size;

// Used by recursively_get_uids, for constraints.

static int *uid_constr_map;
static int uid_constr_vector[MAX_CONSTRAINTS][2];
static int uid_constr_vector_size;

// Used by to keep info about all the uids that matter.

static int *uid_total_map;
static int uid_total_vector[MAX_CONSTRAINTS];
static int uid_total_vector_size;

// Temporary one used to pass to ilp_*

static int uids_t[MAX_CONSTRAINTS];

// We need it to map uid's to integers.
// Will use uid_total_map.

static int uid_counter;
static int uid_total[MAX_CONSTRAINTS];

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

void add_constr(int *input, int size, int type)
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

void add_objective(int *input, int size)
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

//
// For given TID, constructs a uid_objective_vector by 
// recursively iterating over TID's operations.
//

static void recursively_get_uid_objective(int tid, int type)
{
  int id_began_at = uid_objective_vector_size;

  // Add TID's base UID.
  if (uid_objective_map[ID2UID(tid)] == -1)
  {
    uid_objective_vector[uid_objective_vector_size][0] = ID2UID(tid);

    if (type == PROP_ADD)
    {
      uid_objective_vector[uid_objective_vector_size][1] = 1;
    }
    else if (type == PROP_SUB)
    {
      uid_objective_vector[uid_objective_vector_size][1] = -1;
    }

    uid_objective_vector_size++;

    if (uid_objective_vector_size >= MAX_CONSTRAINTS)
    {
      FAIL();
    }

    uid_objective_map[ID2UID(tid)] = uid_counter;

    uid_total[uid_counter++] = ID2UID(tid);

    if (uid_counter > MAX_CONSTRAINTS)
    {
      FAIL();
    }
  }

  // Iterate over TID's operations.
  for (unsigned int i = 0; i < ID2OPSIZE(tid); i++)
  {
    if (ID2OPTYPE(tid, i) == PROP_NEG)
    {
      for (int i = 2*id_began_at; i < 2*uid_objective_vector_size; i++)
      {
        KS[i] *= -1;
      }
    }
    else
    {
      recursively_get_uid_objective(ID2OPVAL(tid, i), ID2OPTYPE(tid, i));
    }
  }
}

static void recursively_get_uid_constr(int id, int type)
{
  int id_began_at = uid_constr_vector_size;

  if (uid_constr_map[ID2UID(id)] == -1)
  {
    uid_constr_vector[uid_constr_vector_size][0] = ID2UID(id);

    if (type == PROP_ADD)
    {
      uid_constr_vector[uid_constr_vector_size][1] = 1;
    }
    else if (type == PROP_SUB)
    {
      uid_constr_vector[uid_constr_vector_size][1] = -1;
    }
    else
    {
      FAIL();
    }

    uid_constr_vector_size++;

    if (uid_constr_vector_size >= MAX_CONSTRAINTS)
    {
      FAIL();
    }

    uid_constr_map[ID2UID(id)] = 1;
  }

  // Add in global ones as well, since we need to find it's constraints as well.
  if (uid_total_map[ID2UID(id)] == -1)
  {
    uid_total_vector[uid_total_vector_size++] = ID2UID(id);
    uid_total_map[ID2UID(id)] = uid_counter;

    if (uid_total_vector_size >= MAX_CONSTRAINTS)
    {
      FAIL();
    }

    uid_total[uid_counter++] = ID2UID(id);

    if (uid_counter > MAX_CONSTRAINTS)
    {
      FAIL();
    }
  }

  for (unsigned int i = 0; i < ID2OPSIZE(id); i++)
  {
    if (ID2OPTYPE(id, i) == PROP_NEG)
    {
      for (int i = 2*id_began_at; i < 2*uid_constr_vector_size; i++)
      {
        KS[i] *= -1;
      }
    }
    else
    {
      recursively_get_uid_constr(ID2OPVAL(id, i), ID2OPTYPE(id, i));
    }
  }
}

int solve_ilp_for_id(int id DBG_END_TAINTING_FUNC)
{
  LDEBUG("ILP:\tStarting ILP for ID#%d OPS %d.\n", id, ID2OPSIZE(id));

  uid_counter = 1;

  reset_KS();

  // Construct the objectve function.
  for(int i = 0; i < MAX_UID; i++) 
           uid_objective_map[i] = -1;
  uid_objective_vector_size = 0;

  recursively_get_uid_objective(id, PROP_ADD);

  // Copy the uid's to TOTAL vector.

  uid_total_vector_size = uid_objective_vector_size;

  for (int i = 0; i < MAX_UID; i++)
  {
    uid_total_map[i]    = uid_objective_map[i];
  }

  for (int i = 0; i < MAX_CONSTRAINTS; i++)
  {
    uid_total_vector[i] = uid_objective_vector[i][0];
  }

  LDUMP("ILP:\tPrinting objective: \n");

  for (int i = 0; i < uid_objective_vector_size; i++) 
  {
    LDUMP("%d*%d (%d)  ", uid_objective_vector[i][1], uid_objective_vector[i][0], 
                                uid_total_map[uid_objective_vector[i][0]]);
  }

  LDUMP("\n");

  for (int i = 0; i < uid_objective_vector_size; i++) 
  {
    uids_t[i] = uid_total_map[uid_objective_vector[i][0]];

    if (uid_objective_vector[i][1] == -1)
    {
      KS[2*i]*= -1;
      KS[2*i + 1]*= -1;
    }
  }

  set_add_rowmode(lp, FALSE);

  add_objective(uids_t, uid_objective_vector_size);

  reset_KS();

  /*
  For each UID from TOTAL vector, which we got while constructing objective, get constraint lists,
  while adding new UIDs as we proceed
  */

  while (uid_total_vector_size > 0)
  {
    int curr_uid = uid_total_vector[--uid_total_vector_size];

    // Before moving on to group restrictions, add direct ones.
    if (uid_[curr_uid].bounded & TAINT_BOUND_LOW)
    {
      add_constr(&uid_total_map[curr_uid], 1, LE);
    }

    if (uid_[curr_uid].bounded & TAINT_BOUND_HIGH)
    {
      add_constr(&uid_total_map[curr_uid], 1, GE);
    }

    if (uid_[curr_uid].bounded & TAINT_BOUND_FIX)
    {
      add_constr(&uid_total_map[curr_uid], 1, EQ);
    }   

    Group_restriction *gr = uid_[curr_uid].gr;

    while (gr != NULL)
    {
      // Add this gr as a constraint.
      int constrained_id = gr -> id;

      for(int i = 0; i < MAX_UID; i++) 
              uid_constr_map[i] = -1;
      uid_constr_vector_size = 0;

      recursively_get_uid_constr(constrained_id, PROP_ADD);

      LDUMP("ILP:\tPrinting constraint: \n");

      for (int i = 0; i < uid_constr_vector_size; i++) 
      {
        LDUMP("%d*%d (%d)  ", uid_constr_vector[i][1], uid_constr_vector[i][0], 
                                 uid_total_map[uid_constr_vector[i][0]]);
      }

      LDUMP("[%d]\n", gr -> bound_type);

      set_add_rowmode(lp, TRUE);

      for (int i = 0; i < uid_constr_vector_size; i++) 
      {
        uids_t[i] = uid_total_map[uid_constr_vector[i][0]];

        if (uid_constr_vector[i][1] == -1)
        {
          KS[2*i]*= -1;
          KS[2*i + 1]*= -1;
        }
      }

      if (gr -> bound_type & TAINT_BOUND_LOW)
      {
        add_constr(uids_t, uid_constr_vector_size, LE);
      }
      if (gr -> bound_type & TAINT_BOUND_HIGH)
      {
        add_constr(uids_t, uid_constr_vector_size, GE);
      }
      if (gr -> bound_type & TAINT_BOUND_FIX)
      {
        add_constr(uids_t, uid_constr_vector_size, LE);
        add_constr(uids_t, uid_constr_vector_size, GE);
      }

      reset_KS();

      gr = gr -> next;
    }
  }

  LDUMP("ILP:\tPrinting total: \n");

  for (int i = 1; i < uid_counter; i++) 
  {
    LDUMP("%d (%d)  ", uid_total[i], uid_total_map[uid_total[i]]);
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

void finish_ilp()
{
  free(uid_objective_map);
  free(uid_constr_map);
  free(uid_total_map);

  delete_lp(lp);
}


void init_ilp()
{
  lp = make_lp(0, ILP_MAX_CONSTR);
  
  set_outputstream(lp, logfile_stream);

  if (lp == NULL)
  {
    DIE("ERROR! Failed making LP\n");
  }

  uid_objective_map = (int *) malloc(MAX_UID * sizeof (int));
  uid_constr_map = (int *) malloc(MAX_UID * sizeof (int));
  uid_total_map = (int *) malloc(MAX_UID * sizeof (int));

  if (uid_objective_map == NULL || uid_constr_map == NULL || uid_total_map == NULL)
  {
    FAIL();
  }
}

int solve_ilp(int *ids DBG_END_TAINTING_FUNC)
{
  // First, flush DR logs so ours get placed at correct location.
  dr_flush_file(logfile);

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

  // Before we exit, flush our logs.
  fflush(logfile_stream);

  if (vulnerables >= MIN_VULNERABILITIES)
  {
    return -1;
  }

  return 1;
}