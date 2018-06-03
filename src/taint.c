#define LOGTEST
#undef LOGDEBUG
#undef  LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"
#include "drsyms.h"

#define LIBC_NAME "libc.so.6"
#define LD_LINUX  "ld-linux-x86-64.so.2"

static int setcc_to_jcc(int opcode)
{
  switch (opcode)
  {
    case OP_seto:
    return OP_jo;
    
    case OP_setno:
    return OP_jno;
    
    case OP_setb:
    return OP_jb;
    
    case OP_setnb:
    return OP_jnb;
    
    case OP_setz:
    return OP_jz;
    
    case OP_setnz:
    return OP_jnz;
    
    case OP_setbe:
    return OP_jbe;
    
    case OP_setnbe:
    return OP_jnbe;
    
    case OP_sets:
    return OP_js;
    
    case OP_setns:
    return OP_jns;
    
    case OP_setp:
    return OP_jp;
    
    case OP_setnp:
    return OP_jnp;
    
    case OP_setl:
    return OP_jl;
    
    case OP_setnl:
    return OP_jnl;
    
    case OP_setle:
    return OP_jle;
    
    case OP_setnle:
    return OP_jnle;
    
    default:
    FAIL();
  }
}

int direction_clear(uint64 eflags)
{
  return (eflags & (1 << 10)) == 0;
}

static int get_A_of_size(int size)
{
  if (size == 1) return DR_REG_AL;
  if (size == 2) return DR_REG_AX;
  if (size == 4) return DR_REG_EAX;
  if (size == 8) return DR_REG_RAX;

  FAIL();
}

void nshr_taint_mv_mem2mem(int src_seg_reg, int src_base_reg, int src_index_reg, int src_scale, int src_disp, 
                                  int dst_seg_reg, int dst_base_reg, int dst_index_reg, int dst_scale, int dst_disp, int access_size DBG_END_TAINTING_FUNC)
{
  reg_t src_addr = decode_addr(src_seg_reg, src_base_reg, src_index_reg, src_scale, src_disp DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2mem(src_addr, dst_seg_reg, dst_base_reg, dst_index_reg, dst_scale, dst_disp, access_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_constmem2mem(uint64 src_addr, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC)
{
  reg_t dst_addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "MEM %p -> MEM %p size %d.\n", 
             src_addr, dst_addr, access_size);

  for (int i = 0; i < access_size; i++)
  {
    int index1 = mem_taint_find_index(src_addr, i);
    int index2 = mem_taint_find_index(dst_addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index1, src_addr + i) || MEMTAINTED(index2, dst_addr + i)), 
                       "  MEM %p TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(src_addr + i), MEMTAINTVAL(index1, src_addr + i),
                               ADDR(dst_addr + i), MEMTAINTVAL(index2, dst_addr + i), index1, access_size);

    MEMTAINT2MEMTAINT(index1, src_addr + i, index2, dst_addr + i);
  }
}

void nshr_taint_mv_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "REG %s -> MEM %p size %d.\n", 
  	         REGNAME(src_reg), addr, REGSIZE(src_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (REGTAINTED(src_reg, i) || MEMTAINTED(index, addr + i)), 
    	                 "  REG %s byte %d TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                               ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, REGSIZE(src_reg));

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
                       "  REG %s byte %d TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i), ADDR(addr + i), 
                               MEMTAINTVAL(index, addr + i), index, REGSIZE(src_reg));

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
                      "  MEM %p TAINT#%d -> REG %s byte %d TAINT#%d INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                              i, REGTAINTVAL(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(index, addr + i, dst_reg, i);
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
                      "\tMEM %p TAINT#%d->\t REG %s byte %d TAINT#%d INDEX %d TOTAL %d.\n", 
                          ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                              i, REGTAINTVAL(dst_reg, i), index, extended_from_size);

    MEMTAINT2REGTAINT(index, addr + i, dst_reg, i);
  }

  for (unsigned int i = extended_from_size; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

  	/*
  	 Quite tricky, try this before we see it fail.
  	 This just puts last byte's taint ID to all 'extended' bytes. 
  	*/

  	MEMTAINT2REGTAINT(index, addr + extended_from_size - 1, dst_reg, i);
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
                       "  MEM %p TAINT#%d -> REG %s byte %d TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                               i, REGTAINTVAL(dst_reg, i), index, REGSIZE(dst_reg));

    MEMTAINT2REGTAINT(index, addr + i, dst_reg, i);
  }
}


int process_restrictor_id(int id1, int id2, int type)
{
   FAIL();
}

int process_restrictor_imm(int id1, unsigned char imm2, int type)
{
  FAIL();
}

void nshr_taint_rest_imm2reg(uint64_t value, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  unsigned char *val_bytes = (unsigned char *) &value;

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int dst_id   = REGTAINTVAL(dst_reg, i);

    if (dst_id > 0)
    {
      found = 1;

      int newid = process_restrictor_imm(dst_id, val_bytes[i], type);

      SETREGTAINTVAL(dst_reg, i, newid);

      update_eflags(type, i, newid, -1);
    }
  }

  if (!found)
  {
    invalidate_eflags();
  }
}

void nshr_taint_strsto_rep(int size DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();

  if (!direction_clear(mcontext.xflags)) FAIL();

  reg_t bytes = reg_get_value(DR_REG_ECX, &mcontext);

  reg_t reg = get_A_of_size(size);

  char *di = (char *) reg_get_value(DR_REG_RDI, &mcontext);
  
  uint64_t daddr = (uint64_t) di;

  for (unsigned int i = 0; i < bytes; i++)
  {
    for (int j = 0; j < size; j++)
    {
      int index = mem_taint_find_index(daddr, i*size + j);

      LDUMP_TAINT(i, (REGTAINTED(reg, j) || MEMTAINTED(index, daddr + i*size + j)), 
                       "  REG %s byte %d TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           REGNAME(reg), j, REGTAINTVAL(reg, j), ADDR(daddr + i*size + j), 
                                MEMTAINTVAL(index, daddr + i*size + j), index, bytes*size);

      REGTAINT2MEMTAINT(reg, j, index, daddr + i*size + j);
    }
  }
}

// Proceeds before first non-equal or ecx
void nshr_taint_strcmp_rep(int size DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();

  if (!direction_clear(mcontext.xflags)) FAIL();

  reg_t bytes = reg_get_value(DR_REG_ECX, &mcontext);

  int equals = 1;

  if (size == 1)
  {
    char *si = (char *) reg_get_value(DR_REG_RSI, &mcontext);
    char *di = (char *) reg_get_value(DR_REG_RDI, &mcontext);


    for (unsigned int i = 0; i < bytes; i++)
    {
      if (*(si + i) != *(di + i))
      {
        equals = 0;

        break;
      }
    }

    invalidate_eflags();

    uint64_t saddr = (uint64_t) si;
    uint64_t daddr = (uint64_t) di;

    if (equals == 1)
    {
      for (unsigned int i = 0; i < bytes; i++)
      {
        int index1 = mem_taint_find_index(saddr, i);
        int index2 = mem_taint_find_index(daddr, i);

        LDUMP_TAINT(i, (MEMTAINTED(index1, saddr)), 
                      "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(saddr + i), MEMTAINTVAL(index1, saddr + i), index1, size);

        MEMTAINTRM(index2, saddr + i);

        LDUMP_TAINT(i, (MEMTAINTED(index2, daddr)), 
                      "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(daddr + i), MEMTAINTVAL(index2, daddr + i), index2, size);

        MEMTAINTRM(index2, daddr + i);
      }
    }
  }
  else
  {
  	FAIL();
  }
}

// Problematic due stupid gcc optimizing divisions by constants to multiplication & shifts.
// This one looks more or less safe, generally very hard to decide when to untaint.
void nshr_taint_shift_imm(int dst_reg, int64 value, int type DBG_END_TAINTING_FUNC)
{
  if (REGTAINTEDANY(dst_reg))
  {
    float p = value;

    p /= (8*REGSIZE(dst_reg));

    if (p > DETAINT_SHIFT)
    {
      REGTAINTRMALL(dst_reg);
    }
    else if (p < IGNORE_SHIFT)
    {
      return;
    }
    else
    {
      FAIL();
    }
  }
}


void nshr_taint_shift_reg(int dst_reg, int src_reg, int type DBG_END_TAINTING_FUNC)
{
  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int id   = REGTAINTVAL(dst_reg, i);

    if (id > 0)
    {
      FAIL();
    }
  }
}

void nshr_taint_rest_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int src_id   = REGTAINTVAL(src_reg, i);
    int dst_id   = REGTAINTVAL(dst_reg, i);

    if (src_id > 0 || dst_id > 0)
    {
      found = 1;

      int newid;

      if (src_id > 0 && dst_id > 0)      newid = process_restrictor_id(src_id, dst_id, type);
      else if (src_id > 0 && dst_id < 0) newid = process_restrictor_imm(src_id, REGVAL(dst_reg, i), type);
      else if (src_id < 0 && dst_id > 0) newid = process_restrictor_imm(dst_id, REGVAL(src_reg, i), type);
      else                               FAIL();

      SETREGTAINTVAL(dst_reg, i, newid);

      update_eflags(type, i, src_id, newid);
    }
  }

  if (!found)
  {
    invalidate_eflags();
  }
}


void nshr_taint_rest_imm2mem(uint64_t value, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);
  
  int found = 0;

  unsigned char *val_bytes = (unsigned char *) &value;

  for (int i = 0; i < access_size; i++)
  {    
    int index = mem_taint_find_index(addr, i);

    int dst_id   = MEMTAINTVAL(index, addr + i);

    if (dst_id > 0)
    {
      found = 1;

      int newid = process_restrictor_imm(dst_id, val_bytes[i], type);

      SETMEMTAINTVAL(index, addr + i, newid);

      update_eflags(type, i, newid, -1);
    }
  }

  if (!found)
  {
    invalidate_eflags();
  }
}

void nshr_taint_rest_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_id   = MEMTAINTVAL(index, addr + i);
    int dst_id   = REGTAINTVAL(dst_reg, i);

    if (src_id > 0 || dst_id > 0)
    {
      found = 1;

      int newid;

      if (src_id > 0 && dst_id > 0)      newid = process_restrictor_id(src_id, dst_id, type);
      else if (src_id > 0 && dst_id < 0) newid = process_restrictor_imm(src_id, REGVAL(dst_reg, i), type);
      else if (src_id < 0 && dst_id > 0) newid = process_restrictor_imm(dst_id, MEMVAL(addr + i),   type);
      else                               FAIL();

      SETREGTAINTVAL(dst_reg, i, newid);

      FAIL(); // JUST don't remember if I should put (src_id, newid) or (newid, src_id) in update_eflags

      update_eflags(type, i, src_id, newid);
    }
  }

  if (!found)
  {
    invalidate_eflags();
  }
}


void nshr_taint_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2reg(addr, dst_reg DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regzx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2regzx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regsx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2regsx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_reg(int src_reg DBG_END_TAINTING_FUNC)
{
  check_bounds_reg(src_reg DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size DBG_END_TAINTING_FUNC)
{
  // First, we check if any memory can be referenced (done inside decode_addr)
  // Second, we check if memory that we referenced is (tained || bounded)

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  check_bounds_mem(addr, size DGB_END_CALL_ARG);
}

static void process_cond_statement(int type, int taken DBG_END_TAINTING_FUNC)
{  
  if (!is_valid_eflags())
  {
    FAIL();
  }

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
      FAILIF(t1[i] != t2[i]);

    t2 = NULL;
  }
  else
  {
    FAIL();
  }

  // For some conditions we only know about special cases.
  // Check all of them here.
  if (type == COND_SIGN_BIT || type == COND_NOT_SIGN_BIT)
  {
    if (eflags_type != PROP_TEST)
    {
      FAIL();
    }
  }

  // This case should be covered by !is_valid_eflags()
  FAILIF(t1 == NULL && t2 == NULL);

  LDUMP_TAINT(0, true, "Updating bounds (taken=%d).\n", taken);

  if (taken) // taken.
  {
    FAILIF(t1 != NULL && t2 != NULL);

    if (t2 == NULL)
    {
      if      (type == COND_LESS)           bound(t1, TAINT_BOUND_HIGH);
      else if (type == COND_MORE)           bound(t1, TAINT_BOUND_LOW);
      else if (type == COND_NONZERO)        {} // Gives no info.
      else if (type == COND_ZERO)           bound(t1, TAINT_BOUND_FIX);
      else if (type == COND_LESS_UNSIGNED)  bound(t1, TAINT_BOUND_LOW | TAINT_BOUND_HIGH);
      else if (type == COND_MORE_UNSIGNED)  {} // Gives no info
      else if (type == COND_SIGN_BIT)       bound(t1, TAINT_BOUND_HIGH);
      else if (type == COND_NOT_SIGN_BIT)   bound(t1, TAINT_BOUND_LOW);
      else                                  FAIL();
    }
    else if (t1 == NULL)
    {
      if      (type == COND_LESS)           bound(t2, TAINT_BOUND_LOW);
      else if (type == COND_MORE)           bound(t2, TAINT_BOUND_HIGH);
      else if (type == COND_NONZERO)        {} // Gives no info.
      else if (type == COND_ZERO)           bound(t2, TAINT_BOUND_FIX);
      else if (type == COND_LESS_UNSIGNED)  {} // Gives no info
      else if (type == COND_MORE_UNSIGNED)  bound(t2, TAINT_BOUND_LOW | TAINT_BOUND_HIGH);
      else                                  FAIL();
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
      if      (type == COND_LESS)           bound(t1, TAINT_BOUND_LOW);
      else if (type == COND_MORE)           bound(t1, TAINT_BOUND_HIGH);
      else if (type == COND_NONZERO)        bound(t1, TAINT_BOUND_FIX);
      else if (type == COND_ZERO)           {} // Gives no info.
      else if (type == COND_LESS_UNSIGNED)  {} // Gives no info
      else if (type == COND_MORE_UNSIGNED)  bound(t1, TAINT_BOUND_LOW | TAINT_BOUND_HIGH);
      else if (type == COND_SIGN_BIT)       bound(t1, TAINT_BOUND_LOW);
      else if (type == COND_NOT_SIGN_BIT)   bound(t1, TAINT_BOUND_HIGH);
      else                                  FAIL();
    }
    else if (t1 == NULL)
    {
      if      (type == COND_LESS)           bound(t2, TAINT_BOUND_HIGH);
      else if (type == COND_MORE)           bound(t2, TAINT_BOUND_LOW);
      else if (type == COND_NONZERO)        bound(t2, TAINT_BOUND_FIX);
      else if (type == COND_ZERO)           {} // Gives no info.
      else if (type == COND_LESS_UNSIGNED)  bound(t2, TAINT_BOUND_LOW | TAINT_BOUND_HIGH);
      else if (type == COND_MORE_UNSIGNED)  {} // Gives no info
      else                                  FAIL();
    }
    else
    {
      FAIL();
    }
  }
}

void nshr_taint_cond_set_reg(int dst_reg, int type, instr_t *instr DBG_END_TAINTING_FUNC)
{
  if (is_valid_eflags())
  {
    FAIL(); // Not yet tested!

    GET_CONTEXT();

    int opcode_old = instr_get_opcode(instr);
    
    int opcode = setcc_to_jcc(opcode_old);

    /*
    FIXME: Workaround because DR is missing correct functionality.
    */

    instr_set_opcode(instr, opcode);

    int taken = instr_jcc_taken(instr, mcontext.xflags);

    process_cond_statement(type, taken DGB_END_CALL_ARG);
  }

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    REGTAINTRM(dst_reg, i);
  }
}

void nshr_taint_cond_jmp(instr_t *instr, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  if (!is_valid_eflags())
  {
  	return;
  }
  
  GET_CONTEXT();

  int taken = instr_jcc_taken(instr, mcontext.xflags);

  process_cond_statement(type, taken DGB_END_CALL_ARG);
}

void nshr_taint_cmp_reg2constmem(int reg1, uint64_t addr, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(reg1); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int t1 = REGTAINTVAL(reg1, i);
    int t2 = MEMTAINTVAL(index, addr + i);

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

void nshr_taint_cmp_reg2mem(int reg1, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_cmp_reg2constmem(reg1, addr, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_reg2reg(int reg1, int reg2, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (unsigned int i = 0; i < REGSIZE(reg1); i++)
  {
  	int t1 = REGTAINTVAL(reg1, i);
  	int t2 = REGTAINTVAL(reg2, i);

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
  	int t1 = REGTAINTVAL(reg1, i);

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
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_cmp_constmem2reg(addr, size, reg2, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_mem2imm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  nshr_taint_cmp_constmem2imm(addr, size, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_constmem2reg(uint64_t addr, int size, int reg2, int type DBG_END_TAINTING_FUNC)
{
  int found = 0;

  for (int i = 0; i < size; i++)
  {
    int index = mem_taint_find_index(addr, i);

  	int t1 = MEMTAINTVAL(index, addr + i);
  	int t2 = REGTAINTVAL(reg2, i);

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

  	int t1 = MEMTAINTVAL(index, addr + i);

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
                      "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, access_size);

    MEMTAINTRM(index, addr + i);
  }
}

void nshr_taint_mv_baseindexmem_rm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size  DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "REMOVE MEM %p size %d\n", addr, access_size);

  for (int i = 0; i < access_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index, addr + i)), 
                      "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, access_size);

    MEMTAINTRM(index, addr + i);
  }
}

void nshr_taint_cond_mv_reg2reg(int src_reg, int dst_reg, instr_t *instr, int type DBG_END_TAINTING_FUNC)
{
  if (!is_valid_eflags())
  {
    return;
  }

  GET_CONTEXT();  

  int taken = instr_cmovcc_triggered(instr, mcontext.xflags);
  
  dr_printf("taken: %d.\n", taken);

  process_cond_statement(type, taken DGB_END_CALL_ARG);

  if (taken)
  {
    nshr_taint_mv_reg2reg(src_reg, dst_reg DGB_END_CALL_ARG);
  }
}

void nshr_taint_mv_reg2regneg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "NEGATING REG %s size %d -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSIZE(dst_reg));


  FAILIF(REGSIZE(src_reg) > REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    if (REGTAINTED(src_reg, i))
    {
      int newid = nshr_tid_modify_id_by_symbol(REGTAINTVAL(src_reg, i), PROP_NEG, 0);

      LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
                       "  REG %s byte %d TAINT#%d NEGATED TO %d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                             REGNAME(src_reg), i, REGTAINTVAL(src_reg, i), newid,
                                 REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

      SETREGTAINTVAL(dst_reg, i, newid);
    }
    else
    {
      REGTAINTRM(dst_reg, i);
    }
  }

  if (REGSIZE(dst_reg) > REGSIZE(src_reg))
  {
    FAIL();
  }
}

void nshr_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  // mask1 -> mask2

  LDEBUG_TAINT(false, "REG %s size %d -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSIZE(dst_reg));


  FAILIF(REGSIZE(src_reg) > REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
                     "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

    REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
  }

  if (REGSIZE(dst_reg) > REGSIZE(src_reg))
  {
    FAIL(); // how does it come here?

    /*
  	FAILIF(REGSIZE(dst_reg) != 2*REGSIZE(src_reg));

    for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
    {
      LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
      	               "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                             REGNAME(src_reg), i - REGSIZE(src_reg), REGTAINTVAL(src_reg, i),
                                 REGNAME(dst_reg), i,
                                     REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(src_reg, i - REGSIZE(src_reg), dst_reg, i);
    }
    */
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
    	               "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i),size);

    REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i - REGSIZE(src_reg), REGTAINTED(dst_reg, i), 
    	              "  REMOVE REG %s byte %d TAINT#%d TOTAL %d.\n", 
                         REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i),
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
                     "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), src_index, REGTAINTVAL(src_reg, src_index),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));


    REGTAINT2REGTAINT(src_reg, src_index, dst_reg, i);
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
    	               "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(src_reg));

    REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
  }

  for (unsigned int i = REGSIZE(src_reg); i < REGSIZE(dst_reg); i++)
  {

  	/*
  	 Quite tricky, try this before we see it fail.
  	 This just puts last byte's taint ID to all 'extended' bytes. 
  	*/

    REGTAINT2REGTAINT(src_reg, REGSIZE(src_reg) - 1, dst_reg, i);
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

    int src_taint = MEMTAINTVAL(index, addr + i);
    int dst_taint = REGTAINTVAL(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d [L8].\n", 
                         newid, REGNAME(dst_reg), i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#%d -> REG %s byte %d TAINT#%d INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                                 i, REGTAINTVAL(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(index, addr + i, dst_reg, i);
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
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "DOING '%s' by REG %s -> MEM %p size %d.\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), addr, REGSIZE(src_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_taint = REGTAINTVAL(src_reg, i);
    int dst_taint = MEMTAINTVAL(index, addr + i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to MEM %p TOTAL %d [L1].\n", 
                         newid, addr + i, REGSIZE(src_reg));

        SETMEMTAINTVAL(index, addr + i, newid);
      }
    }
    else if (src_taint > 0) // src_reg to dst
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                       REGNAME(src_reg), i, REGTAINTVAL(src_reg, i), 
                             ADDR(addr + i), MEMTAINTVAL(index, addr + i), index, REGSIZE(src_reg));
    }
    else if (dst_taint > 0)
    {
      // nothing to do: dst_taint stays whatever it was.
    }
   }
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "DOING '%s' by MEM %p to REG %s -> REG %s size %d\n", PROP_NAMES[type], 
  	                addr, REGNAME(dst_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int index = mem_taint_find_index(addr, i);

    int src_taint = MEMTAINTVAL(index, addr + i);
    int dst_taint = REGTAINTVAL(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (src_taint != dst_taint)
      {
        int newid = nshr_tid_modify_id_by_symbol(dst_taint, type, src_taint);

        LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d [L2].\n", 
                         newid, REGNAME(dst_reg), i, REGSIZE(dst_reg));

        SETREGTAINTVAL(dst_reg, i, newid);
      }
    }
    else if (src_taint > 0)  // src to dst_reg
    {
      LDUMP_TAINT(i, true, "  MEM %p TAINT#%d -> REG %s byte %d TAINT#%d INDEX %d TOTAL %d.\n", 
                             ADDR(addr + i), MEMTAINTVAL(index, addr + i), REGNAME(dst_reg), 
                                 i, REGTAINTVAL(dst_reg, i), index, REGSIZE(dst_reg));

      MEMTAINT2REGTAINT(index, addr + i, dst_reg, i);
    }
    else
    {
      // Nothing to do.
    }
  }
}

// dst_reg = src_reg+dst_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  // Make sure no such case leaks from instrumentation phase.
  FAILIF(src_reg == dst_reg);
  FAILIF(REGSIZE(src_reg) != REGSIZE(dst_reg));

  LDEBUG_TAINT(false, "DOING '%s' by REG %s and REG %s to REG %s size %d\n", PROP_NAMES[type], 
  	               REGNAME(src_reg), REGNAME(dst_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    int src_taint = REGTAINTVAL(src_reg, i);
    int dst_taint = REGTAINTVAL(dst_reg, i);

    if (src_taint > 0 && dst_taint > 0)
    {
      int newid = nshr_tid_modify_id_by_symbol(src_taint, type, dst_taint);

      LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d [L3].\n", 
                       newid, REGNAME(dst_reg), i, REGSIZE(src_reg));

      SETREGTAINTVAL(dst_reg, i, newid);
    }
    else if (src_taint > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                       REGNAME(src_taint), i, REGTAINTVAL(src_taint, i),
                             REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));


      REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
    }
  }
}

void nshr_taint_mv_reg_rm(int mask DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REMOVE REG %s size %d\n", REGNAME(mask), REGSIZE(mask));

  for (unsigned int i = 0; i < REGSIZE(mask); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(mask, i)), "  REMOVE REG %s byte %d TAINT#%d TOTAL %d.\n", 
                       REGNAME(mask), i, REGTAINTVAL(mask, i), REGSIZE(mask));

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
      int newid = nshr_tid_new_uid(fd);
      dr_printf("  ADD MEM %p mark %d TAINT#%d INDEX %d TOTAL %d.\n", 
      	                 ADDR(addr + i), nshr_tid_new_iid_get(), newid, index, size);

      SETMEMTAINTVAL(index, addr + i, newid);
    }
  }
}

//dst_reg = index_reg + base_reg
void nshr_taint_mv_2coeffregs2reg(int index_reg, int base_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "REG %s + REG %s size %d -> REG %s size %d.\n", 
             REGNAME(index_reg), REGNAME(base_reg), REGSIZE(base_reg), REGNAME(dst_reg), REGSIZE(index_reg));

  FAILIF(REGSIZE(base_reg) != REGSIZE(index_reg));

  int size = MIN(REGSIZE(base_reg), REGSIZE(dst_reg));

  for (int i = 0; i < size; i++)
  {
    int t1 = REGTAINTVAL(base_reg, i);
    int t2 = REGTAINTVAL(index_reg, i);

    if (t1 > 0 && t2 > 0)
    {
      int newid;

      // else SPECIALCASE: taintID + taintID = taintID (taint stays the same)
      if (t1 != t2)
      {
        newid = nshr_tid_modify_id_by_symbol(t1, PROP_ADD, t2);
      }
      else
      {
      	newid = t1;
      }

      LDUMP_TAINT(i, true, "  Assign ID#%d to REG %s byte %d TOTAL %d [L7].\n", 
                       newid, REGNAME(dst_reg), i, size);

      SETREGTAINTVAL(dst_reg, i, newid);
    }
    else if (t1 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(base_reg), i, REGTAINTVAL(base_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(base_reg, i, dst_reg, i);
    }
    else if (t2 > 0)
    {
      LDUMP_TAINT(i, true, "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(index_reg), i, REGTAINTVAL(index_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

      REGTAINT2REGTAINT(index_reg, i, dst_reg, i);
    }
    else
    {
      REGTAINTRM(dst_reg, i);
    }
  }

  for (unsigned int i = REGSIZE(base_reg); i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i - REGSIZE(base_reg), REGTAINTED(dst_reg, i), 
    	              "  REMOVE REG %s byte %d TAINT#%d TOTAL %d.\n", 
                         REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i),
                             REGSIZE(dst_reg) - REGSIZE(base_reg));

    REGTAINTRM(dst_reg, i);
  }
}

static void process_jump(app_pc pc, int is_ret DBG_END_TAINTING_FUNC)
{
  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
     LDUMP_TAINT(0, true, "Ignoring jump to %llx.\n", pc);

     dr_free_module_data(data);

     return;
  }

  static handleFunc return_from_libc = NULL;

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
  	  LDUMP_TAINT(0, true, "Returning to Active mode in %s[%s] at %s %s:%d.\n", 
                       sym.name, modname, data -> full_path, sym.file, sym.line);
    }
    else
    {
  	  LDUMP_TAINT(0, true, "Returning to Active mode in [%s] at %s.\n", modname, data -> full_path);
    }

    started_ = MODE_ACTIVE;

    dr_free_module_data(data);

    if (return_from_libc != NULL)
    {
      (*return_from_libc)(DGB_END_CALL_ARG_ALONE);
    }

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
  	LDUMP_TAINT(0, true, "Detected call to %s[%s] at %s  %s:%d.\n", sym.name, modname, data -> full_path, 
                                          sym.file, sym.line);
  }
  else
  {
  	LDUMP_TAINT(0, true, "Missing symbols for call to [%s] at %s.\n", modname, data -> full_path);
  }

  if (strcmp(LD_LINUX, modname) == 0 || strcmp(LIBC_NAME, modname) == 0)
  {

  	LDUMP_TAINT(0, true, "Goind into MODE_IN_LIBC mode.\n");

  	started_ = MODE_IN_LIBC;

    if (strcmp(sym.name, "__libc_start_main") != 0 &&
        strcmp(sym.name, "_dl_fini") != 0)
    {
      handleFunc *handler = hashtable_lookup(&func_hashtable, pc);

      if (handler != NULL) 
      {
        // Call pre-funciton.
        if (handler[0] != NULL)
        {
          handler[0](DGB_END_CALL_ARG_ALONE);
        }

        // Register post-function.
        return_from_libc = handler[1];
      }
      else
      {
        FAIL();
      }
    }
  }

  // DON'T FORGET IT!
  dr_free_module_data(data);
}


void nshr_taint_check_ret(DBG_END_TAINTING_FUNC_ALONE)
{
  GET_CONTEXT();
  
  reg_t pc = *((uint64_t *) reg_get_value(DR_REG_RSP, &mcontext));

  process_jump((unsigned char *) pc, 1 DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_reg(int reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t pc = reg_get_value(reg, &mcontext);

  process_jump((unsigned char *) pc, 0 DGB_END_CALL_ARG);
}


void nshr_taint_check_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp DGB_END_CALL_ARG);

  reg_t pc = *((reg_t *) addr);

  process_jump((unsigned char *) pc, 0 DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_immed(uint64_t pc DBG_END_TAINTING_FUNC)
{
  process_jump((unsigned char *) pc, 0 DGB_END_CALL_ARG);
}


void nshr_taint_div(int dividend1_reg, int dividend2_reg, int divisor_reg, int quotinent_reg, int remainder_reg DBG_END_TAINTING_FUNC)
{
  int divident1_tainted = REGTAINTEDANY(dividend1_reg);
  int divident2_tainted = REGTAINTEDANY(dividend2_reg);
  int divisor_tainted   = REGTAINTEDANY(divisor_reg);

  // Don't know what to do....
  if (divident1_tainted)
  {
    FAIL();
  }

  // Just copy taint to quotinent, remove from remainder (it's tainted but bounded, so ignore)
  if (divisor_tainted == 0)
  {
    FAILIF(REGSIZE(dividend2_reg) != REGSIZE(quotinent_reg));

    nshr_taint_mv_reg2reg(dividend2_reg, quotinent_reg DGB_END_CALL_ARG);

    nshr_taint_mv_reg_rm(remainder_reg DGB_END_CALL_ARG);
  }
  else
  {
    // Hard to tell what is the right decision, for now let's opt for 'safest'. Do the same.
    FAILIF(REGSIZE(dividend2_reg) != REGSIZE(quotinent_reg));

    nshr_taint_mv_reg2reg(dividend2_reg, quotinent_reg DGB_END_CALL_ARG);

    nshr_taint_mv_reg_rm(remainder_reg DGB_END_CALL_ARG);
  }
}

void nshr_taint_mul_reg2reg(int src1_reg, int src2_reg, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC)
{
  int src1_tainted = REGTAINTEDANY(src1_reg);
  int src2_tainted = REGTAINTEDANY(src2_reg);

  if (!src1_tainted && !src2_tainted)
  {
    return;
  }

  if (src1_tainted && src2_tainted)
  {
    int newid = nshr_make_id_by_merging_all_ids_in2regs(src1_reg, src2_reg);

    for (unsigned int i = 0; i < REGSIZE(dst1_reg); i++)
    {
      SETREGTAINTVAL(dst1_reg, i, newid);
    }

    if (dst2_reg != DR_REG_NULL)
    {
      for (unsigned int i = 0; i < REGSIZE(dst2_reg); i++)
      {
        SETREGTAINTVAL(dst2_reg, i, newid);
      }
    }
  }
  else
  {
    GET_CONTEXT();

    if (src1_tainted)
    {
      reg_t bytes = reg_get_value(src2_reg, &mcontext);

      nshr_taint_mul_imm2reg(src1_reg, bytes, dst1_reg, dst2_reg DGB_END_CALL_ARG);
    }
    else
    {
      reg_t bytes = reg_get_value(src1_reg, &mcontext);

      nshr_taint_mul_imm2reg(src2_reg, bytes, dst1_reg, dst2_reg DGB_END_CALL_ARG);
    }
  }
}

// Maybe we can do something more accurate later....
void nshr_taint_mul_imm2reg(int src1_reg, int64 value, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC)
{
  int src1_tainted = REGTAINTEDANY(src1_reg);

  if (!src1_tainted)
  {
    return;
  }
  
  int newid = nshr_make_id_by_merging_all_ids_in2regs(src1_reg, src1_reg);

  if (value < 0)
  {
    newid = nshr_tid_modify_id_by_symbol(newid, PROP_NEG, 0);
  }

  for (unsigned int i = 0; i < REGSIZE(dst1_reg); i++)
  {
    SETREGTAINTVAL(dst1_reg, i, newid);
  }

  if (dst2_reg != DR_REG_NULL)
  {
    for (unsigned int i = 0; i < REGSIZE(dst2_reg); i++)
    {
      SETREGTAINTVAL(dst2_reg, i, newid);
    }
  }
}