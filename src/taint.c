#define LOGTEST
#undef LOGDEBUG
#undef  LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

const char *reg_mask_names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", 
                                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

#define LIBC_NAME "libc.so.6"

int find_index(reg_t addr, int i)
{
	int index = 0;

    while(!MEMTAINTISEMPTY(index, addr + i) && 
              MEMTAINTADDR(index, addr + i) != addr &&
                  index < TAINTMAP_NUM)
    {
      index++;
    }

    if (index == TAINTMAP_NUM)
    {
      FAIL();
    }

    return index;
}

void nshr_taint_mv_reg2mem(int segment, int src_reg, int disp, int scale, int base_reg, int index_reg)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "Taint:\t\tDECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "Taint:\t\tREG %s start %d->\t\t MEM %p size %d.\n", 
  	         REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINT(src_reg, i) > 0 || MEMTAINTVAL(index, addr + i) > 0), 
    	                 "Taint:\t\t\tREG %s byte %d TAINT#%d->\t\t MEM %p TAINT #%d INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINT(src_reg, i),
                               ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, REGSIZE(src_reg));

    MEMTAINTADDR(index, addr + i) = addr + i;
    MEMTAINTVAL(index, addr + i) = REGTAINT(src_reg, i);
  }
}

void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr)
{
  LDEBUG_TAINT(false, "Taint:\t\tREG %s start %d->\t\t MEM %p size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), addr, REGSIZE(src_reg)); 

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTVAL(index, addr + i) > 0 || REGTAINT(src_reg, i) > 0),
                       "Taint:\t\t\tREG %s byte %d TAINT #%d->\t\t MEM %p TAINT #%d INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINT(src_reg, i), ADDR(addr + i), 
                               MEMTAINTVAL(index, addr + i), index, REGSIZE(src_reg));

    MEMTAINTADDR(index, addr + i) = addr + i;
    MEMTAINTVAL(index, addr + i) = REGTAINT(src_reg, i);
  } 
}

void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg)
{
  LDEBUG_TAINT(false, "Taint:\t\tMEM %p->\t REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));  

  for (int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = find_index(addr, i);


    LDUMP_TAINT(i, (REGTAINT(dst_reg, i) > 0 || MEMTAINTVAL(index, addr + i) > 0), 
                       "Taint:\t\t\tMEM %p TAINT #%d->\t\t REG %s byte %d TAINT #%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINT(dst_reg, i), index, REGSIZE(dst_reg));

    REGTAINT(dst_reg, i) = MEMTAINTVAL(index, addr + i);
  }
}

void nshr_taint_mv_mem2regzx(int segment, int disp, int scale, int base_reg, int index_reg, int dst_reg, int srcsize)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "Taint:\t\tDECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "Taint:\t\tMEM %p->\t REG %s start %d size %d zero extended to %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), srcsize, REGSIZE(dst_reg));


  for (int i = 0; i < srcsize; i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINT(dst_reg, i) > 0 || MEMTAINTVAL(index, addr + i) > 0),
                      "Taint:\t\t\tMEM %p TAINT #%d->\t\t REG %s byte %d TAINT #%d INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                              REGSTART(dst_reg) + i, REGTAINT(dst_reg, i), index, srcsize);

    REGTAINT(dst_reg, i) = MEMTAINTVAL(index, addr + i);
  }

  for (int i = srcsize; i < REGSIZE(dst_reg); i++)
  {
  	REGTAINT(dst_reg, i) = -1;
  }
}

void nshr_taint_mv_mem2reg(int segment, int disp, int scale, int base_reg, int index_reg, int dst_reg)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "Taint:\t\tDECODED: base %p index %d scale %d disp %d.\n", 
                     base, index, scale, disp);

  LDEBUG_TAINT(false, "Taint:\t\tMEM %p->\t REG %s start %d size %d.\n", 
             addr, REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(dst_reg));

  for (int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINT(dst_reg, i) > 0 || MEMTAINTVAL(index, addr + i) > 0),
                       "Taint:\t\t\tMEM %p TAINT #%d->\t\t REG %s byte %d TAINT #%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                               REGSTART(dst_reg) + i, REGTAINT(dst_reg, i), index, REGSIZE(dst_reg));

    REGTAINT(dst_reg, i) = MEMTAINTVAL(index, addr + i);
  }
}

void nshr_taint_mv_mem_rm(uint64 addr, int size)
{
  LDEBUG_TAINT(false, "Taint:\t\tREMOVE MEM %p size %d\n", addr, size);

  for (int i = 0; i < size; i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTVAL(index, addr + i) > 0), 
                      "Taint:\t\t\tREMOVE\t\t\t\t MEM %p TAINT #%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, size);

    MEMTAINTVAL(index, addr + i) = -1;
  }
}

void nshr_taint_mv_baseindexmem_rm(int segment, int disp, int scale, int base_reg, int index_reg, int size)
{
  GET_CONTEXT();
  
  reg_t base  = reg_get_value(base_reg, &mcontext);
  reg_t index = reg_get_value(index_reg, &mcontext);

  reg_t addr = base + index*scale + disp;

  LDUMP_TAINT(0, false, "Taint:\t\tDECODED: base %p index %d scale %d disp %d.\n", 
  	                 base, index, scale, disp);

  LDEBUG_TAINT(false, "Taint:\t\tREMOVE\t\t\t\t MEM %p size %d\n", addr, size);

  for (int i = 0; i < size; i++)
  {
    int index = find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTVAL(index, addr + i) > 0), 
                      "Taint:\t\t\tREMOVE MEM %p TAINT #%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, size);

    MEMTAINTVAL(index, addr + i) = -1;
  }
}

void nshr_taint_mv_reg2reg(int src_reg, int dst_reg)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "Taint:\t\tREG %s start %d->\t\t REG %s start %d size %d.\n", 
             REGNAME(src_reg), REGSTART(src_reg), REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(src_reg));

  for (int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINT(dst_reg, i) > 0 || REGTAINT(src_reg, i) > 0), 
    	               "Taint:\t\t\tREG %s byte %d TAINT #%d->\t\t\t REG %s byte %d TAINT #%d TOTAL %d.\n", 
                           REGNAME(src_reg), REGSTART(src_reg) + i, REGTAINT(src_reg, i),
                               REGNAME(dst_reg), REGSTART(dst_reg) + i,
                                   REGTAINT(dst_reg, i), REGSIZE(src_reg));

    REGTAINT(dst_reg, i) = REGTAINT(src_reg, i);
  }
}

void nshr_taint_ret()
{
  GET_CONTEXT();
  
  reg_t address = *((reg_t *) reg_get_value(DR_REG_RSP, &mcontext));

  module_data_t *data = dr_lookup_module((app_pc) address);

  if (data == NULL)
  {
     LDEBUG_TAINT(false, "Taint:\t\t\tJUMPING to unknown address %llx.\n", address);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  LDEBUG_TAINT(false, "Taint:\t\t\tJUMPING to '%s' at address %llx.\n", modname, address);

  if (strcmp(modname, LIBC_NAME) != 0)
  {
    LDEBUG_TAINT(true, "Taint:\t\tRETURNING to '%s'\n", modname);

    started_ = MODE_ACTIVE;
  }

  dr_free_module_data(data);
}

void nshr_taint_jmp_reg(int dst_reg)
{
  LDEBUG_TAINT(true, "Taint:\t\tJUMPING to '%s'\n", REGNAME(dst_reg));

  GET_CONTEXT();
  
  reg_t base  = reg_get_value(dst_reg, &mcontext);
}

void nshr_taint_mix_val2reg(int dst_reg, int64 value, int type)
{
  LDEBUG_TAINT(false, "Taint:\t\tDOING '%s' by 0x%x to\t\t REG % s size %d\n", PROP_NAMES[type], value, 
  	         REGNAME(dst_reg), REGSIZE(dst_reg));

  for (int i = 0; i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINT(dst_reg, i) > 0), "Taint:\t\t\tDOING '%s' by 0x%x to %s byte %d TAINT #%d.\n", 
                       PROP_NAMES[type], value, REGNAME(dst_reg), REGSTART(dst_reg) + i, REGTAINT(dst_reg, i));

    if (REGTAINT(dst_reg, i) > 0)
    {
    }
  }
}

void nshr_taint_mv_reg_rm(int mask)
{
  LDEBUG_TAINT(false, "Taint:\t\tREMOVE\t\t\t\t REG %s start %d size %d\n", REGNAME(mask), REGSTART(mask), REGSIZE(mask));

  for (int i = 0; i < REGSIZE(mask); i++)
  {
    LDUMP_TAINT(i, (REGTAINT(mask, i) > 0), "Taint:\t\t\tREMOVE REG %s byte %d TAINT #%d TOTAL %d.\n", 
                       REGNAME(mask), REGSTART(mask) + i, REGTAINT(mask, i), REGSIZE(mask));

    REGTAINT(mask, i) = -1;
  }
}

void nshr_taint(reg_t addr, unsigned int size, int fd)
{
  int iid = nshr_tid_new_iid_get();

  LDEBUG_TAINT(true, "Taint:\t\tADD MEM %p size %d mark %d\n", addr, size, iid);

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
      LDUMP_TAINT(i, false, "Taint:\t\t\tADD MEM %p mark %d TAINT #%d INDEX %d TOTAL %d.\n", 
      	                 ADDR(addr + i), iid, MEMTAINTVAL(index, addr + i), index, size);

      MEMTAINTADDR(index, addr + i) = addr + i;
      MEMTAINTVAL(index, addr + i) = nshr_tid_new_uid(fd);
    }
  }
}

void nshr_taint_mv_2coeffregs2reg(int index_reg, int scale, int base_reg, int disp, int dst_reg)
{
  LDEBUG_TAINT(false, "Taint:\t\tREG %s*%d start %d + REG %s start %d ->\t\t REG %s start %d size %d.\n", 
             REGNAME(index_reg), scale, REGSTART(index_reg), REGNAME(base_reg), REGSTART(base_reg), 
                 REGNAME(dst_reg), REGSTART(dst_reg), REGSIZE(index_reg));


  if (scale > 1 || disp != 0)  // Make sure index_reg has correct taint size
  {
  	nshr_reg_fix_size(index_reg);
  }

  for (int i = 0; i < REGSIZE(index_reg); i++)
  {
    if (REGTAINT(index_reg, i) > 0 && REGTAINT(base_reg, i) > 0)
    {
    	FAIL();
    }
    
    if (REGTAINT(index_reg, i) > 0) // we have dst = index_reg*scale + disp
    {
      REGTAINT(dst_reg, i) = nshr_tid_change_id(REGTAINT(index_reg, i), PROP_MULT, scale, 0);
    }
  } 
}