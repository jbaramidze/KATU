#define LOGTEST
#define LOGDEBUG
#define  LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

#define LIBC_NAME "libc.so.6"

void nshr_taint_mv_reg2mem(int src_reg, int segment, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "REG %s start %d -> MEM %p size %d.\n", 
  	         REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(src_reg, i) || MEMTAINTED(index, addr + i)), 
    	                 "  REG %s byte %d TAINT#[%d %d %d %d] -> MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s start %d -> MEM %p size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg)); 

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i) || REGTAINTED(src_reg, i)),
                       "  REG %s byte %d TAINT#[%d %d %d %d] -> MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i), ADDR(addr + i), 
                               MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_constmem2regzx(uint64 addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{

  LDEBUG_TAINT(false, "MEM %p -> REG %s start %d size %d zero extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), extended_from_size, REGSIZE(dst_reg));

  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
  	REGTAINTRM(dst_reg, i);
  }
}

void nshr_taint_mv_constmem2regsx(uint64 addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "MEM %p->\t REG %s start %d size %d sign extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), extended_from_size, REGSIZE(dst_reg));


  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

  	/*
  	FIXME: Quite tricky, try this before we see it fail.
  	       This just puts 0th byte's taint ID to all 'extended' bytes. 
  	*/

  	MEMTAINT2REGTAINT(dst_reg, i, index, addr + extended_from_size - 1);
  }
}

void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "MEM %p -> REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));  

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);


    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)), 
                       "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }
}

void nshr_taint_mv_mem2regzx(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "MEM %p -> REG %s start %d size %d zero extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), extended_from_size, REGSIZE(dst_reg));


  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
  	REGTAINTRM(dst_reg, i);
  }
}

void nshr_taint_mv_mem2regsx(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "MEM %p->\t REG %s start %d size %d sign extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), extended_from_size, REGSIZE(dst_reg));


  for (int i = 0; i < extended_from_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

  	/*
  	FIXME: Quite tricky, try this before we see it fail.
  	       This just puts 0th byte's taint ID to all 'extended' bytes. 
  	*/

  	MEMTAINT2REGTAINT(dst_reg, i, index, addr + extended_from_size - 1);
  }
}

void nshr_taint_mv_mem2reg(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "MEM %p -> REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                       "MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));



    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }
}

void nshr_taint_jmp(DBG_END_TAINTING_FUNC_ALONE)
{
  GET_CONTEXT();

  int res = instr_jcc_taken(instr, mcontext.xflags);

  if (eflags_.last_affecting_opcode != PROP_CMP)
  {
  	FAIL();
  }
}

void nshr_taint_cmp(DBG_END_TAINTING_FUNC_ALONE)
{
  GET_CONTEXT();

  update_eflags(PROP_CMP);
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

void nshr_taint_mv_baseindexmem_rm(int segment, int base_reg, int index_reg, int scale, int disp, int access_size  DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
  	                 base, index, scale, disp);

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

  LDEBUG_TAINT(false, "REG %s start %d size %d -> REG %s start %d size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));


  if (REGSIZE(src_reg) != REGSIZE(dst_reg))
  {
  	FAIL();
  }

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }
}

void nshr_taint_mv_reg2regzx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s start %d size %d zero extend to -> REG %s start %d size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));

  int size = MIN(REGSIZE(src_reg), REGSIZE(dst_reg));

  for (int i = 0; i < size; i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i),size);

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i - REGSIZE(src_reg), REGTAINTED(dst_reg, i), 
    	              "  REMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                         REGNAME(dst_reg), REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i),
                             REGSIZE(dst_reg) - REGSIZE(src_reg));

    REGTAINTRM(dst_reg, i);
  }
}

void nshr_taint_mv_reg2regsx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s start %d size %d sign extend to -> REG %s start %d size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));


  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(src_reg));

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {

  	/*
  	FIXME: Quite tricky, try this before we see it fail.
  	       This just puts 0th byte's taint ID to all 'extended' bytes. 
  	*/

    REGTAINT2REGTAINT(dst_reg, i, src_reg, 0);
  }
}

void nshr_taint_ret(DBG_END_TAINTING_FUNC_ALONE)
{
  GET_CONTEXT();
  
  reg_t address = *((reg_t *) reg_get_value(DR_REG_RSP, &mcontext));

  module_data_t *data = dr_lookup_module((app_pc) address);

  if (data == NULL)
  {
     LDEBUG_TAINT(false, "  JUMPING to unknown address %llx.\n", address);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  LDEBUG_TAINT(false, "  JUMPING to '%s' at address %llx.\n", modname, address);

  if (strcmp(modname, LIBC_NAME) != 0)
  {
    LDEBUG_TAINT(true, "RETURNING to '%s'\n", modname);

    started_ = MODE_ACTIVE;
  }

  dr_free_module_data(data);
}

void nshr_taint_jmp_reg(int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(true, "JUMPING to '%s'\n", REGNAME(dst_reg));

  GET_CONTEXT();
  
  reg_t base  = reg_get_value(dst_reg, &mcontext);
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_constmem2reg(uint64 addr, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "DOING '%s' by MEM %p -> REG %s start %d size %d.\n", PROP_NAMES[type],
                   addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));  

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
                         newid, REGNAME(dst_reg), REGSTART(dst_reg) + i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                                 REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
  }
}

// dst = dst+src_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2mem(int src_reg, int segment, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "DOING '%s' by REG %s start %d -> MEM %p size %d.\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg));

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
                       REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i), 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
   }
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_mem2reg(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();

  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "DOING '%s' by MEM %p to REG %s start %d size %d\n", PROP_NAMES[type], 
  	                addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));

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
                         newid, REGNAME(dst_reg), REGSTART(dst_reg) + i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                                 REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
  }
}

// dst = dst+src_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{ 
  if (REGSIZE(dst_reg) != REGSIZE(src_reg))
  {
  	FAIL();
  }

  // Make sure no such case leaks from instrumentation phase.
  if (src_reg == dst_reg)
  {
  	FAIL();
  }

  LDEBUG_TAINT(false, "DOING '%s' by '%s' TAINT#[%d %d %d %d] to REG %s TAIND#[%d %d %d %d] size %d\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), REGTAINTVALS_LOG(src_reg, 0), REGNAME(dst_reg), 
  	                   REGTAINTVALS_LOG(dst_reg, 0), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int src_taint = REGTAINTVAL1(src_reg, i);
    int dst_taint = REGTAINTVAL1(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, i, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d.\n", 
                         newid, REGNAME(dst_reg), REGSTART(dst_reg) + i, REGSIZE(src_reg));

        SETREGTAINTVAL(dst_reg, i, 0, newid);
      }
    }
    else if (src_taint > 0)  // dst_reg to src_reg
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                             REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                                 REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                     REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
  }
}

void nshr_taint_mv_reg_rm(int mask DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE REG %s start %d size %d\n", REGNAME(mask), REGSTART(mask), REGSIZE(mask));

  for (unsigned int i = 0; i < REGSIZE(mask); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(mask, i)), "  REMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                       REGNAME(mask), REGSTART(mask) + i, REGTAINTVALS_LOG(mask, i), REGSIZE(mask));

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
  LDEBUG_TAINT(false, "REG %s start %d + REG %s start %d size %d -> REG %s start %d size %d.\n", 
             REGNAME(index_reg), REGSTART(index_reg), REGNAME(base_reg), REGSTART(base_reg), REGSIZE(base_reg),
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(index_reg));

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
                       newid, REGNAME(dst_reg), REGSTART(dst_reg) + i, size);

      SETREGTAINTVAL(dst_reg, i, 0, newid);
    }
    else if (t1 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(base_reg), REGSTART(base_reg) + i, REGTAINTVALS_LOG(base_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(dst_reg, i, base_reg, i);
    }
    else if (t2 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#[%d %d %d %d] -> REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(index_reg), REGSTART(index_reg) + i, REGTAINTVALS_LOG(index_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
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
                         REGNAME(dst_reg), REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i),
                             REGSIZE(dst_reg) - REGSIZE(base_reg));

    REGTAINTRM(dst_reg, i);
  }
}