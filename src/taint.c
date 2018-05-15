#define LOGTEST
#define LOGDEBUG
#undef  LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"
#include "drsyms.h"

#define LIBC_NAME "libc.so.6"
#define LD_LINUX  "ld-linux-x86-64.so.2"

void nshr_taint_mv_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  LDEBUG_TAINT(false, "REG %s -> MEM %p size %d.\n", 
  	         REGNAME(src_reg), addr, REGSIZE(src_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(src_reg, i) || MEMTAINTED(index, addr + i)), 
    	                 "  REG %s byte %d TAINT#[%d %d %d %d] -> MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i),
                               ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s -> MEM %p size %d.\n", 
             REGNAME(src_reg), addr, REGSIZE(src_reg)); 

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i) || REGTAINTED(src_reg, i)),
                       "  REG %s byte %d TAINT#[%d %d %d %d] -> MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i), ADDR(addr + i), 
                               MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_constmem2regzx(uint64 addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{

  LDEBUG_TAINT(false, "MEM %p -> REG %s size %d zero extended to %d.\n", 
             addr, REGNAME(dst_reg), extended_from_size, REGSIZE(dst_reg));

  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
  	REGTAINTRM(dst_reg, i);
  }
}

void nshr_taint_mv_constmem2regsx(uint64 addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "MEM %p->\t REG %s size %d sign extended to %d.\n", 
             addr, REGNAME(dst_reg), extended_from_size, REGSIZE(dst_reg));


  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

  	/*
  	 Quite tricky, try this before we see it fail.
  	 This just puts last byte's taint ID to all 'extended' bytes. 
  	*/

  	MEMTAINT2REGTAINT(dst_reg, i, index, addr + extended_from_size - 1);
  }
}

void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "MEM %p -> REG %s size %d.\n", 
             addr, REGNAME(dst_reg), REGSIZE(dst_reg));  

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);


    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)), 
                       "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                               i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(base_reg  DGB_END_CALL_ARG);
  check_bounds_reg(index_reg DGB_END_CALL_ARG);

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  nshr_taint_mv_constmem2reg(addr, dst_reg DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regzx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(base_reg DGB_END_CALL_ARG);
  check_bounds_reg(index_reg DGB_END_CALL_ARG);

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  nshr_taint_mv_constmem2regzx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regsx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(base_reg DGB_END_CALL_ARG);
  check_bounds_reg(index_reg DGB_END_CALL_ARG);
  
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  nshr_taint_mv_constmem2regsx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_reg(int src_reg DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(src_reg DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size DBG_END_TAINTING_FUNC)
{
  // First, we check if any memory can be referenced.
  // Second, we check if memory that we referenced is (tained || bounded)

  check_bounds_reg(base_reg DGB_END_CALL_ARG);
  check_bounds_reg(index_reg DGB_END_CALL_ARG);

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  check_bounds_mem(addr, size DGB_END_CALL_ARG);
}

void nshr_taint_cond_jmp(enum cond_type type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  if (!is_valid_eflags())
  {
  	return;
  }
  
  GET_CONTEXT();

  int taken = instr_jcc_taken(instr, mcontext.xflags);

  int eflags_type = get_eflags_type();

  int *t1, *t2;

  if (eflags_type == PROP_CMP)
  {
    t2 = get_taint2_eflags(); // array of 8
    t1 = get_taint1_eflags(); // array of 8
  }
  else if (eflags_type == PROP_TEST)
  {
    t2 = get_taint2_eflags(); // array of 8
    t1 = get_taint1_eflags(); // array of 8

    // Make sure test %%x %%x was done.
    for (int i = 0; i < 8; i++)
      if (t1[i] != t2[i]) FAIL();

    t2 = NULL;
  }
  else
  {
    FAIL();
  }

  // This case should be covered by !is_valid_eflags()
  if (t1 == NULL && t2 == NULL)
  {
    FAIL();
  }

  LDUMP_TAINT(0, true, "Updating bounds (taken=%d).\n", taken);

  if (taken) // taken.
  {
    if (t1 != NULL && t2 != NULL)
    {
      FAIL();
    }
    else if (t2 == NULL)
    {
      if      (type == COND_LESS)    bound(t1, TAINT_BOUND_LOW);
      else if (type == COND_MORE)    bound(t1, TAINT_BOUND_HIGH);
      else if (type == COND_NONZERO) {} // Gives no info.
      else if (type == COND_ZERO)    bound(t1, TAINT_BOUND_FIX);
      else                           FAIL();
    }
    else if (t1 == NULL)
    {
      if      (type == COND_LESS)    bound(t2, TAINT_BOUND_HIGH);
      else if (type == COND_MORE)    bound(t2, TAINT_BOUND_LOW);
      else if (type == COND_NONZERO) {} // Gives no info.
      else if (type == COND_ZERO)    bound(t2, TAINT_BOUND_FIX);
      else                           FAIL();
    }
    else
    {
      FAIL();
    }
  }
  else
  {
    if (t1 != NULL && t2 != NULL)
    {
      FAIL();
    }
    else if (t2 == NULL)
    {
      if      (type == COND_LESS)    bound(t1, TAINT_BOUND_HIGH);
      else if (type == COND_MORE)    bound(t1, TAINT_BOUND_LOW);
      else if (type == COND_NONZERO) bound(t1, TAINT_BOUND_FIX);
      else if (type == COND_ZERO)    {} // Gives no info.
      else                           FAIL();
    }
    else if (t1 == NULL)
    {
      if      (type == COND_LESS)    bound(t2, TAINT_BOUND_LOW);
      else if (type == COND_MORE)    bound(t2, TAINT_BOUND_HIGH);
      else if (type == COND_NONZERO) bound(t2, TAINT_BOUND_FIX);
      else if (type == COND_ZERO)    {} // Gives no info.
      else                           FAIL();
    }
    else
    {
      FAIL();
    }
  }
}

void nshr_taint_cmp_reg2mem(int reg1, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(reg1); i++)
  {
    int index = mem_taint_find_index(addr, i);

  	int t1 = REGTAINTVAL1(reg1, i);
  	int t2 = MEMTAINTVAL1(index, addr + i);

  	if (t1 > 0 || t2 > 0)
  	{
  	  found = 1;

      update_eflags(PROP_CMP, i, t1, t2);
  	}
  }

  if (!found)
  {
  	invalidate_eflags();
  }
}

void nshr_taint_cmp_reg2reg(int reg1, int reg2, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(reg1); i++)
  {
  	int t1 = REGTAINTVAL1(reg1, i);
  	int t2 = REGTAINTVAL1(reg2, i);

  	if (t1 > 0 || t2 > 0)
  	{
  	  found = 1;

      update_eflags(type, i, t1, t2);
  	}
  }

  if (!found)
  {
  	invalidate_eflags();
  }
}

void nshr_taint_cmp_reg2imm(int reg1, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(reg1); i++)
  {
  	int t1 = REGTAINTVAL1(reg1, i);

  	if (t1 > 0)
  	{
  	  found = 1;

      update_eflags(type, i, t1, -1);
  	}
  }

  if (!found)
  {
  	invalidate_eflags();
  }
}

void nshr_taint_cmp_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int reg2, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  nshr_taint_cmp_constmem2reg(addr, size, reg2, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_mem2imm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  nshr_taint_cmp_constmem2imm(addr, size, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_constmem2reg(uint64_t addr, int size, int reg2, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

  	int t1 = MEMTAINTVAL1(index, addr + i);
  	int t2 = REGTAINTVAL1(reg2, i);

  	if (t1 > 0 || t2 > 0)
  	{
  	  found = 1;

      update_eflags(type, i, t1, t2);
  	}
  }

  if (!found)
  {
  	invalidate_eflags();
  }
}

void nshr_taint_cmp_constmem2imm(uint64_t addr, int size, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

  	int t1 = MEMTAINTVAL1(index, addr + i);

  	if (t1 > 0)
  	{
  	  found = 1;

      update_eflags(type, i, t1, -1);
  	}
  }

  if (!found)
  {
  	invalidate_eflags();
  }
}

void nshr_taint_mv_mem_rm(uint64 addr, int access_size DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE MEM %p size %d\n", addr, access_size);

  for (int i = 0; i < access_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i)), 
                      "  REMOVE MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, access_size);

    MEMTAINTRM(index, addr + i);
  }
}

void nshr_taint_mv_baseindexmem_rm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size  DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  LDEBUG_TAINT(false, "REMOVE MEM %p size %d\n", addr, access_size);

  for (int i = 0; i < access_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i)), 
                      "  REMOVE MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, access_size);

    MEMTAINTRM(index, addr + i);
  }
}

void nshr_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s size %d -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSIZE(dst_reg));


  if (REGSIZE(src_reg) > REGSIZE(dst_reg))
  {
  	FAIL();
  }

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  if (REGSIZE(dst_reg) > REGSIZE(src_reg))
  {
  	if (REGSIZE(dst_reg) != 2*REGSIZE(src_reg)) FAIL();

    for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
    {
      LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
      	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                             REGNAME(src_reg), i - REGSIZE(src_reg), REGTAINTVALS_LOG(src_reg, i),
                                 REGNAME(dst_reg), i,
                                     REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, src_reg, i - REGSIZE(src_reg));
    }
  }
}

void nshr_taint_mv_reg2regzx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s size %d zero extend to -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  int size = MIN(REGSIZE(src_reg), REGSIZE(dst_reg));

  for (int i = 0; i < size; i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i),size);

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i - REGSIZE(src_reg), REGTAINTED(dst_reg, i), 
    	              "  REMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                         REGNAME(dst_reg), i, REGTAINTVALS_LOG(dst_reg, i),
                             REGSIZE(dst_reg) - REGSIZE(src_reg));

    REGTAINTRM(dst_reg, i);
  }
}


void nshr_taint_mv_regbyte2regsx(int src_reg, int src_index, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s byte %d copied to whole REG %s size %d.\n", 
             REGNAME(src_reg), src_index, REGNAME(dst_reg), REGSIZE(dst_reg));  

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, src_index)), 
                     "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), src_index, REGTAINTVALS_LOG(src_reg, src_index),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));


    REGTAINT2REGTAINT(dst_reg, i, src_reg, src_index);
  }
}

void nshr_taint_mv_reg2regsx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s size %d sign extend to -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), REGNAME(dst_reg), REGSIZE(dst_reg));


  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(src_reg));

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {

  	/*
  	 Quite tricky, try this before we see it fail.
  	 This just puts last byte's taint ID to all 'extended' bytes. 
  	*/

    REGTAINT2REGTAINT(dst_reg, i, src_reg, REGSIZE(src_reg) - 1);
  }
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_constmem2reg(uint64 addr, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "DOING '%s' by MEM %p -> REG %s size %d.\n", PROP_NAMES[type],
                   addr, REGNAME(dst_reg), REGSIZE(dst_reg));  

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_taint = MEMTAINTVAL1(index, addr + i);
    int dst_taint = REGTAINTVAL1(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, i, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d.\n", 
                         newid, REGNAME(dst_reg), i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                                 i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
  }
}

// dst = dst+src_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  LDEBUG_TAINT(false, "DOING '%s' by REG %s -> MEM %p size %d.\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), addr, REGSIZE(src_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_taint = REGTAINTVAL1(src_reg, i);
    int dst_taint = MEMTAINTVAL1(index, addr + i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, i, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to MEM %p TOTAL %d.\n", 
                         newid, addr + i, REGSIZE(src_reg));

        SETMEMTAINTVAL1(index, addr + i, newid);
      }
    }
    else if (src_taint > 0) // src_reg to dst
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                       REGNAME(src_reg), i, REGTAINTVALS_LOG(src_reg, i), 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
   }
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_memNreg2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int src2_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  LDEBUG_TAINT(false, "DOING '%s' by MEM %p to REG %s -> REG %s size %d\n", PROP_NAMES[type], 
  	                addr, REGNAME(src2_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_taint = MEMTAINTVAL1(index, addr + i);
    int dst_taint = REGTAINTVAL1(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, i, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d.\n", 
                         newid, REGNAME(dst_reg), i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                                 i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
  }
}

// dst = src1_reg+src2_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_regNreg2reg(int src1_reg, int src2_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  // Make sure no such case leaks from instrumentation phase.
  if (src1_reg == dst_reg && src2_reg == dst_reg)
  {
  	FAIL();
  }

  LDEBUG_TAINT(false, "DOING '%s' by REG %s and REG %s to REG %s size %d\n", PROP_NAMES[type], 
  	               REGNAME(src1_reg), REGNAME(src2_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(src1_reg); i++)
  {
    int src1_taint = REGTAINTVAL1(src1_reg, i);
    int src2_taint = REGTAINTVAL1(src2_reg, i);
    int dst_taint  = REGTAINTVAL1(dst_reg, i);

    if (src1_taint > 0 && src2_taint > 0)
    {
      if (src1_taint != src2_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(src1_taint, i, type, src2_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d.\n", 
                         newid, REGNAME(dst_reg), i, REGSIZE(src1_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
      else
      {
        if (REGTAINTVAL1(dst_reg, i) != src1_taint)
        {
           LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                             REGNAME(src1_reg), i, REGTAINTVALS_LOG(src1_reg, i),
                                 REGNAME(dst_reg), i,
                                     REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

          SETREGTAINTVAL(dst_reg, i, 0, src1_taint);
        }
      }
    }
    else if (src1_taint > 0 && src1_taint != dst_taint)  // dst_reg to src_reg
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                             REGNAME(src1_reg), i, REGTAINTVALS_LOG(src1_reg, i),
                                 REGNAME(dst_reg), i,
                                     REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, src1_reg, i);
    }
    else if (src2_taint > 0 && src2_taint != dst_taint)  // dst_reg to src_reg
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                             REGNAME(src2_reg), i, REGTAINTVALS_LOG(src2_reg, i),
                                 REGNAME(dst_reg), i,
                                     REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, src2_reg, i);
    }
    else
    {
      // Do nothing.
    }
  }
}

void nshr_taint_mv_reg_rm(int mask DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE REG %s size %d\n", REGNAME(mask), REGSIZE(mask));

  for (unsigned int i = 0; i < REGSIZE(mask); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(mask, i)), "  REMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                       REGNAME(mask), i, REGTAINTVALS_LOG(mask, i), REGSIZE(mask));

    REGTAINTRM(mask, i);

  }
}

void nshr_taint(reg_t addr, unsigned int size, int fd)
{
  LDEBUG("ADD MEM %p size %d mark %d\n", addr, size, nshr_tid_new_iid_get());

  for (unsigned int i = 0; i < size; i++)
  {
    int index = 0;
  
    while(index < TAINTMAP_NUM && !MEMTAINTISEMPTY(index, addr + i))
    {
      index++;
    }
    
    if (index == TAINTMAP_NUM)
    {
      FAIL();
    }
    else
    {
      LDUMP("  ADD MEM %p mark %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
      	                 ADDR(addr + i), nshr_tid_new_iid_get(), MEMTAINTVALS_LOG(index, addr + i), index, size);

      SETMEMTAINTVAL1(index, addr + i, nshr_tid_new_uid(fd));
    }
  }
}

//dst_reg = index_reg + base_reg
void nshr_taint_mv_2coeffregs2reg(int index_reg, int base_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s + REG %s size %d -> REG %s size %d.\n", 
             REGNAME(index_reg), REGNAME(base_reg), REGSIZE(base_reg), REGNAME(dst_reg), REGSIZE(index_reg));

  if (REGSIZE(base_reg) != REGSIZE(index_reg))
  {
  	FAIL();
  }

  int size = MIN(REGSIZE(base_reg), REGSIZE(dst_reg));

  for (int i = 0; i < size; i++)
  {
    int t1 = REGTAINTVAL1(base_reg, i);
    int t2 = REGTAINTVAL1(index_reg, i);

    if (t1 > 0 && t2 > 0)
    {
      int newid;

      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (t1 != t2)
      {
        newid = nshr_tid_modify_id_by_symbol(t1, i, PROP_ADD, t2);
      }
      else
      {
      	newid = t1;
      }

      LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d.\n", 
                       newid, REGNAME(dst_reg), i, size);

      SETREGTAINTVAL(dst_reg, i, 0, newid);
    }
    else if (t1 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(base_reg), i, REGTAINTVALS_LOG(base_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, base_reg, i);
    }
    else if (t2 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(index_reg), i, REGTAINTVALS_LOG(index_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, index_reg, i);
    }
    else
    {
      REGTAINTRM(dst_reg, i);
    }
  }

  for (unsigned int i = REGSIZE(base_reg); i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i - REGSIZE(base_reg), REGTAINTED(dst_reg, i), 
    	              "  REMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                         REGNAME(dst_reg), i, REGTAINTVALS_LOG(dst_reg, i),
                             REGSIZE(dst_reg) - REGSIZE(base_reg));

    REGTAINTRM(dst_reg, i);
  }
}


static void process_jump(app_pc pc DBG_END_TAINTING_FUNC)
{
  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
     LDUMP_TAINT(0, false, "Ignoring jump to %llx.\n", pc);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  drsym_info_t sym;

  char name_buf[1024];
  char file_buf[1024];

  sym.struct_size = sizeof(sym);
  sym.name = name_buf;
  sym.name_size = 1024;
  sym.file = file_buf;
  sym.file_size = 1024;

  drsym_error_t symres;

  if (started_ == MODE_IN_LIBC && (strcmp(modname, LIBC_NAME) != 0 && strcmp(modname, LD_LINUX) != 0))
  {
    symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

  	if (symres == DRSYM_SUCCESS)
    {
  	  LDUMP_TAINT(0, true, "Returning to Active mode in %s[%s] at %s.\n", sym.name, modname, data -> full_path);
    }
    else
    {
  	  LDUMP_TAINT(0, true, "Returning to Active mode in [%s] at %s.\n", modname, data -> full_path);
    }

    started_ = MODE_ACTIVE;

    dr_free_module_data(data);

    return;
  }

  if (started_ == MODE_BEFORE_MAIN)
  {
    symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

    if (strcmp(sym.name, "main") == 0)
    {
      LDEBUG_TAINT(false, "Jumping to main.\n");

      started_ = MODE_ACTIVE;

      dr_free_module_data(data);

      return;
    }
  }

  if (started_ != MODE_ACTIVE)
  {
    dr_free_module_data(data);

  	return;
  }

  symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

  if (symres == DRSYM_SUCCESS)
  {
  	LDUMP_TAINT(0, true, "Detected call to %s[%s] at %s.\n", sym.name, modname, data -> full_path);
  }
  else
  {
  	LDUMP_TAINT(0, true, "Missing symbols for call to [%s] at %s.\n", modname, data -> full_path);
  }

  if (strcmp(LD_LINUX, modname) == 0 || strcmp(LIBC_NAME, modname) == 0)
  {

  	LDUMP_TAINT(0, true, "Goind into MODE_IN_LIBC mode.\n");

  	started_ = MODE_IN_LIBC;
  }

  // DON'T FORGET IT!
  dr_free_module_data(data);
}

void nshr_taint_check_jmp_reg(int reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t pc = reg_get_value(reg, &mcontext);

  process_jump((unsigned char *) pc DGB_END_CALL_ARG);
}


void nshr_taint_check_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  reg_t pc = decode_addr(seg_reg, base_reg, index_reg, scale, disp);

  process_jump((unsigned char *) pc DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_immed(uint64_t pc DBG_END_TAINTING_FUNC)
{
  process_jump((unsigned char *) pc DGB_END_CALL_ARG);
}