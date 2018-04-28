#define LOGTEST
#define LOGDEBUG
#undef  LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

#define LIBC_NAME "libc.so.6"

void nshr_taint_mv_reg2mem(int segment, int src_reg, int disp, int scale, int base_reg, int index_reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "REG %s start %d->\t MEM %p size %d.\n", 
  	         REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(src_reg, i) || MEMTAINTED(index, addr + i)), 
    	                 "\tREG %s byte %d TAINT#[%d %d %d %d]->\t MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    SETMEMTAINTADDR(index, addr + i, addr + i);

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s start %d->\t MEM %p size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg)); 

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i) || REGTAINTED(src_reg, i)),
                       "\tREG %s byte %d TAINT#[%d %d %d %d]->\t MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i), ADDR(addr + i), 
                               MEMTAINTVALS_LOG(index, addr + i), index, REGSIZE(src_reg));

    SETMEMTAINTADDR(index, addr + i, addr + i);

    REGTAINT2MEMTAINT(src_reg, i, index, addr + i);
  }

  DBG_PARAM_CLEANUP(); 
}

void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "MEM %p->\t REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));  

  for (int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);


    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)), 
                       "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_mem2regzx(int segment, int disp, int scale, int base_reg, int index_reg, int dst_reg, int srcsize DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "MEM %p->\t REG %s start %d size %d zero extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), srcsize, REGSIZE(dst_reg));


  for (int i = 0; i < srcsize; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                      "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, srcsize);

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  for (int i = srcsize; i < REGSIZE(dst_reg); i++)
  {
  	REGTAINTRM(dst_reg, i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_mem2reg(int segment, int disp, int scale, int base_reg, int index_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "MEM %p->\t REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));

  for (int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || MEMTAINTED(index, addr + i)),
                       "\tMEM %p TAINT#[%d %d %d %d]->\t REG %s byte %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i), index, REGSIZE(dst_reg));

    MEMTAINT2REGTAINT(dst_reg, i, index, addr + i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_mem_rm(uint64 addr, int size DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE MEM %p size %d\n", addr, size);

  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i)), 
                      "\tREMOVE\t\t\t\t MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, size);

    MEMTAINTRM(index, addr + i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_baseindexmem_rm(int segment, int disp, int scale, int base_reg, int index_reg, int size DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "DECODED: base %p index %d scale %d disp %d.\n", 
  	                 base, index, scale, disp);

  LDEBUG_TAINT(false, "REMOVE\t\t\t\t MEM %p size %d\n", addr, size);

  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i)), 
                      "\tREMOVE MEM %p TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVALS_LOG(index, addr + i), index, size);

    MEMTAINTRM(index, addr + i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s start %d->\t REG %s start %d size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "\tREG %s byte %d TAINT#[%d %d %d %d]->\t\t REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(src_reg));

    REGTAINT2REGTAINT(dst_reg, i, src_reg, i);
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_ret(DBG_END_TAINTING_FUNC_ALONE)
{
  GET_CONTEXT();
  
  reg_t address = *((reg_t *) reg_get_value(DR_REG_RSP, &mcontext));

  module_data_t *data = dr_lookup_module((app_pc) address);

  if (data == NULL)
  {
     LDEBUG_TAINT(false, "\tJUMPING to unknown address %llx.\n", address);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  LDEBUG_TAINT(false, "\tJUMPING to '%s' at address %llx.\n", modname, address);

  if (strcmp(modname, LIBC_NAME) != 0)
  {
    LDEBUG_TAINT(true, "RETURNING to '%s'\n", modname);

    started_ = MODE_ACTIVE;
  }

  dr_free_module_data(data);

  DBG_PARAM_CLEANUP();
}

void nshr_taint_jmp_reg(int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(true, "JUMPING to '%s'\n", REGNAME(dst_reg));

  GET_CONTEXT();
  
  reg_t base  = reg_get_value(dst_reg, &mcontext);

  DBG_PARAM_CLEANUP();
}

// dst = src + value
void nshr_taint_add_val2reg(int src_reg, int dst_reg, int64 value DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s start %d + %d to\t\t REG %s start %d size %d\n", REGNAME(src_reg), 
  	              REGSTART(src_reg), value, REGNAME(dst_reg), REGSTART(dst_reg));

  int newid = nshr_tid_modify_id_by_val(src_reg, PROP_ADD, value);

  if (newid == -1)
  {
  	LDUMP("Not tainted, ignoring.\n");

  	for (int i = 0; i < REGSIZE(src_reg); i++)
    {
      REGTAINTRM(dst_reg, i);
    }

  	return;
  }

  int ind = SIZE_TO_INDEX(REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "\tREG %s byte %d + %d TAINT#[%d %d %d %d]->\t\t REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, value, REGTAINTVALS_LOG(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(src_reg));

    SETREGTAINTVAL(dst_reg, i, ind, nshr_tid_new_iid(newid, i));
  }

  DBG_PARAM_CLEANUP();
}

// dst = dst+src_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2reg(int dst_reg, int src_reg, int type DBG_END_TAINTING_FUNC)
{
  int t1 = nshr_reg_taint_any(dst_reg);
  int t2 = nshr_reg_taint_any(src_reg);

  LDEBUG_TAINT(false, "DOING '%s' by '%s' TAINT#[%d %d %d %d] to\t\t REG %s TAIND#[%d %d %d %d] size %d\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), REGTAINTVALS_LOG(src_reg, 0), REGNAME(dst_reg), 
  	                   REGTAINTVALS_LOG(dst_reg, 0), REGSIZE(dst_reg));


  if (t1 == 0 && t2 == 0)
  {
  	LDUMP("None tainted, ignoring.\n");

  	return;
  }

  if (t1 > 0 && t2 > 0)
  {
    GET_CONTEXT();
    reg_t v1  = reg_get_value(dst_reg, &mcontext);
    reg_t v2  = reg_get_value(src_reg, &mcontext);

    int newid = nshr_tid_modify_id_by_symbol(dst_reg, type, src_reg);

    if (newid == -1) FAIL();

    int ind = SIZE_TO_INDEX(REGSIZE(src_reg));

    for (int i = 0; i < REGSIZE(src_reg); i++)
    {
      LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	                 "\tREG %s byte %d TAINT#[%d %d %d %d] '%s' REG %s byte %d TAINT#[%d %d %d %d]->\t\t REG %s TOTAL %d.\n", 
                             REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i), PROP_NAMES[type],
                                REGNAME(dst_reg), REGSTART(dst_reg) + i, REGTAINTVALS_LOG(dst_reg, i),
                                  REGNAME(dst_reg), REGSIZE(src_reg));

      SETREGTAINTVAL(dst_reg, i, ind, nshr_tid_new_iid(newid, i));
    }

    DBG_PARAM_CLEANUP();
  }
  else if (t1 > 0) // just like dst = dst+value
  {
    GET_CONTEXT();
  
    reg_t value  = reg_get_value(src_reg, &mcontext);

    nshr_taint_mix_val2reg(dst_reg, dst_reg, value, type DGB_END_CALL_ARG);
  }
  else // dst = src + value
  {
    GET_CONTEXT();
  
    reg_t value  = reg_get_value(dst_reg, &mcontext);

    nshr_taint_mix_val2reg(dst_reg, src_reg, value, type DGB_END_CALL_ARG);
  }
}

// dst = src+value (or 1, ^, &, depending on type)
void nshr_taint_mix_val2reg(int dst_reg, int src_reg, int64 value, int type DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "DOING '%s' by 0x%x on %s to\t\t REG %s size %d\n", PROP_NAMES[type], value, 
  	         REGNAME(src_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  int newid = nshr_tid_modify_id_by_val(src_reg, type, value);

  if (newid == -1)
  {
  	LDUMP("Not tainted, ignoring.\n");

  	if (dst_reg != src_reg)
  	{
  	  for (int i = 0; i < REGSIZE(dst_reg); i++)
      {
        REGTAINTRM(dst_reg, i);
      }
    }

  	return;
  }

  int ind = SIZE_TO_INDEX(REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
    	               "\tREG %s byte %d TAINT#[%d %d %d %d] '%s' %d->\t\t REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINTVALS_LOG(src_reg, i),
                                PROP_NAMES[type], value, REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINTVALS_LOG(dst_reg, i), REGSIZE(src_reg));

    SETREGTAINTVAL(dst_reg, i, ind, nshr_tid_new_iid(newid, i));
  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint_mv_reg_rm(int mask DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE\t\t\t\t REG %s start %d size %d\n", REGNAME(mask), REGSTART(mask), REGSIZE(mask));

  for (int i = 0; i < REGSIZE(mask); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(mask, i)), "\tREMOVE REG %s byte %d TAINT#[%d %d %d %d] TOTAL %d.\n", 
                       REGNAME(mask), REGSTART(mask) + i, REGTAINTVALS_LOG(mask, i), REGSIZE(mask));

    REGTAINTRM(mask, i);

  }

  DBG_PARAM_CLEANUP();
}

void nshr_taint(reg_t addr, unsigned int size, int fd)
{
  int iid = nshr_tid_new_iid_get();

  LDEBUG("ADD MEM %p size %d mark %d\n", addr, size, iid);

  for (int i = 0; i < size; i++)
  {
    int index = 0;
  
    while(!MEMTAINTISEMPTY(index, addr + i) && index < TAINTMAP_NUM)
    {
      index++;
    }
    
    if (index == TAINTMAP_NUM)
    {
      FAIL();
    }
    else
    {
      LDUMP("\tADD MEM %p mark %d TAINT#[%d %d %d %d] INDEX %d TOTAL %d.\n", 
      	                 ADDR(addr + i), iid, MEMTAINTVALS_LOG(index, addr + i), index, size);

      SETMEMTAINTADDR(index, addr + i, addr + i);
      SETMEMTAINTVAL1(index, addr + i, nshr_tid_new_uid(fd));
    }
  }
}

void nshr_taint_mv_2coeffregs2reg(int index_reg, int scale, int base_reg, int disp, int dst_reg DBG_END_TAINTING_FUNC)
{
	/*
  LDEBUG_TAINT(false, "REG %s*%d start %d + REG %s start %d ->\t REG %s start %d size %d.\n", 
             REGNAME(index_reg), scale, REGSTART(index_reg), REGNAME(base_reg), REGSTART(base_reg), 
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(index_reg));

  FAIL();

  if (scale > 1 || disp != 0)  // Make sure index_reg has correct taint size
  {
  	//nshr_reg_get_or_fix_sized_taint(index_reg);
  }

  for (int i = 0; i < REGSIZE(index_reg); i++)
  {
    if (REGTAINT(index_reg, i) > 0 && REGTAINT(base_reg, i) > 0)
    {
    	FAIL();
    }
    
    if (REGTAINT(index_reg, i) > 0) // we have dst = index_reg*scale + disp
    {
    }
  } 
  */
}