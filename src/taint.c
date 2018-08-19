#define LOGWARNING
#define LOGNORMAL
#define LOGDEBUG
#define LOGDUMP

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

void memset_reg2mem(int reg, uint64_t addr, int size DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "Doing memset of %d bytes at MEM 0x%llx from %s.\n", size, addr, REGNAME(reg));

  for (int i = 0; i < size; i++)
  {
    for (unsigned int j = 0; j < REGSIZE(reg); j++)
    {
      int index = mem_taint_find_index(addr, i*REGSIZE(reg) + j);

      LDUMP_TAINT(i, (REGTAINTED(reg, j) || MEMTAINTED(index, addr + i*REGSIZE(reg) + j)), 
                       "  REG %s byte %d TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           REGNAME(reg), j, REGTAINTVAL(reg, j), ADDR(addr + i*REGSIZE(reg) + j), 
                                MEMTAINTVAL(index, addr + i*REGSIZE(reg) + j), index, REGSIZE(reg)*size);

      REGTAINT2MEMTAINT(reg, j, index, addr + i*REGSIZE(reg) + j);
    }
  }
}

void update_bounds_strings_equal(uint64_t saddr, uint64_t daddr, int bytes DBG_END_TAINTING_FUNC)
{
  LDEBUG_TAINT(false, "Strings at MEM 0x%llx and MEM 0x%llx compared equal, updating bounds.\n", saddr, daddr);

  for (int i = 0; i < bytes; i++)
  {
    int index1 = mem_taint_find_index(saddr, i);
    int index2 = mem_taint_find_index(daddr, i);

    if (MEMTAINTVAL(index2, daddr + i) == -1)
    {
      LDUMP_TAINT(i, (MEMTAINTED(index1, saddr)), 
                    "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                            ADDR(saddr + i), MEMTAINTVAL(index1, saddr + i), index1, bytes);

      MEMTAINTRM(index1, saddr + i);
    }

    if (MEMTAINTVAL(index1, saddr + i) == -1)
    {
      LDUMP_TAINT(i, (MEMTAINTED(index2, daddr)), 
                    "  REMOVE MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                         ADDR(daddr + i), MEMTAINTVAL(index2, daddr + i), index2, bytes);

      MEMTAINTRM(index2, daddr + i);
    }
  }
}

void nshr_taint_mv_mem2mem(int src_seg_reg, int src_base_reg, int src_index_reg, int src_scale, int src_disp, 
                                  int dst_seg_reg, int dst_base_reg, int dst_index_reg, int dst_scale, int dst_disp, int access_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t src_addr = decode_addr(src_seg_reg, src_base_reg, src_index_reg, src_scale, src_disp, 1 DGB_END_CALL_ARG);
  reg_t dst_addr = decode_addr(dst_seg_reg, dst_base_reg, dst_index_reg, dst_scale, dst_disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2constmem(src_addr, dst_addr, access_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_constmem2mem(uint64 src_addr, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t dst_addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2constmem(src_addr, dst_addr, access_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_constmem2constmem(uint64 src_addr, uint64 dst_addr, uint64_t size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "MEM %p -> MEM %p size %d.\n", 
             src_addr, dst_addr, size);

  for (unsigned int i = 0; i < size; i++)
  {
    int index1 = mem_taint_find_index(src_addr, i);
    int index2 = mem_taint_find_index(dst_addr, i);

    LDUMP_TAINT(i, (MEMTAINTED(index1, src_addr + i) || MEMTAINTED(index2, dst_addr + i)), 
                       "  MEM %p TAINT#%d -> MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                           ADDR(src_addr + i), MEMTAINTVAL(index1, src_addr + i),
                               ADDR(dst_addr + i), MEMTAINTVAL(index2, dst_addr + i), index1, size);

    MEMTAINT2MEMTAINT(index1, src_addr + i, index2, dst_addr + i);
  }
}

void nshr_taint_mv_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_reg2constmem(src_reg, addr DGB_END_CALL_ARG);
}

void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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
  STOP_IF_NOT_ACTIVE();

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

  fix_dest_reg(dst_reg);
}

void nshr_taint_mv_constmem2regsx(uint64 addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  nshr_taint_mv_constmem2regzx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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

  fix_dest_reg(dst_reg);
}


int process_restrictor_id(int *ids1, int *ids2, int size, int type DBG_END_TAINTING_FUNC)
{
  // Nothing to do with restrictions, just make sure taint is or'ed
  if (type == PROP_OR)
  {
    for (int i = 0; i < size; i++)
    { 
      LDUMP_TAINT(i, (ids1[i] == -1 && ids2[i] != -1), 
                      "  Propagating TAINT#%d via 'or' on byte %d, destination TAINT#%d.\n", i, ids2[i], ids1[i]);

      if (ids1[i] == -1 && ids2[i] != -1)
      {
        ids1[i] = ids2[i];
      }
      else if (ids2[i] == -1)
      {
        // Nothing to do.
      }
      else
      {
        FAIL();
      }
    }
  }
  else
  {
    FAIL();
  }

  return 0;
}

void process_restrictor_imm(int *ids, uint64_t imm2, int size, int type DBG_END_TAINTING_FUNC)
{
  if (type == PROP_AND)
  {
    unsigned char *imm_char = (unsigned char *) &imm2;

    for (int i = 0; i < 8; i++)
    {
      int leading_zeros = __builtin_clz(imm_char[i]) - 24;

      if (leading_zeros > 2)
      {
        ids[i] = -1;
      }
    }
  }
  else if (type == PROP_OR || type == PROP_XOR)
  {
    // Ignore OR with immediate.
  }
  else
  {
    FAIL(); 
  }
}

void nshr_taint_rest_imm2reg(uint64_t value, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Restricting %s with 0x%llx, type %s.\n", REGNAME(dst_reg), value, PROP_NAMES[type]);

  if (REGTAINTEDANY(dst_reg))
  {
    int ids[8];
    
    get_reg_taint(dst_reg, ids);

    process_restrictor_imm(ids, value, REGSIZE(dst_reg), type DGB_END_CALL_ARG);

    set_reg_taint(dst_reg, ids);
  }
  else
  {
    invalidate_eflags();
  }
}


void nshr_taint_rest_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Restricting %s with %s, type %s.\n", REGNAME(src_reg), REGNAME(dst_reg), PROP_NAMES[type]);

  int tainted1 = REGTAINTEDANY(src_reg);
  int tainted2 = REGTAINTEDANY(dst_reg);

  int ids1[8];
  int ids2[8];

  get_reg_taint(src_reg, ids1);
  get_reg_taint(dst_reg, ids2);

  if (tainted1 && tainted2)
  {
    process_restrictor_id(ids2, ids1, REGSIZE(dst_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted1)
  {
    process_restrictor_imm(ids1, REGVAL(dst_reg), REGSIZE(dst_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted2)
  {
    process_restrictor_imm(ids2, REGVAL(src_reg), REGSIZE(src_reg), type DGB_END_CALL_ARG);
  }
  else
  {
    invalidate_eflags();
  }

  set_reg_taint(src_reg, ids1);
  set_reg_taint(dst_reg, ids2);
}


void nshr_taint_rest_imm2mem(uint64_t value, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Restricting MEM 0x%llx with 0x%llx, type %s.\n", addr, value, PROP_NAMES[type]);

  if (MEMTAINTEDANY(addr, access_size))
  {
    int ids[8];

    get_mem_taint(addr, access_size, ids);

    process_restrictor_imm(ids, value, access_size, type DGB_END_CALL_ARG);

    set_mem_taint(addr, access_size, ids);
  }
  else
  {
    invalidate_eflags();
  }
}


void nshr_taint_rest_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Restricting MEM %llx with %s, type %s.\n", addr, REGNAME(src_reg), PROP_NAMES[type]);

  int tainted1 = REGTAINTEDANY(src_reg);
  int tainted2 = MEMTAINTEDANY(addr, REGSIZE(src_reg));

  int ids1[8];
  int ids2[8];

  get_reg_taint(src_reg, ids1);
  get_mem_taint(addr, REGSIZE(src_reg), ids2);

  if (tainted1 && tainted2)
  {
    process_restrictor_id(ids1, ids2, REGSIZE(src_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted1)
  {
    process_restrictor_imm(ids1, MEMVAL(addr), REGSIZE(src_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted2)
  {
    process_restrictor_imm(ids2, REGVAL(src_reg), REGSIZE(src_reg), type DGB_END_CALL_ARG);
  }
  else
  {
    invalidate_eflags();
  }

  set_reg_taint(src_reg, ids1);
  set_mem_taint(addr, REGSIZE(src_reg), ids2);
}

void nshr_taint_rest_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Restricting %s with MEM %llx, type %s.\n", REGNAME(dst_reg), addr, PROP_NAMES[type]);

  int tainted1 = MEMTAINTEDANY(addr, REGSIZE(dst_reg));
  int tainted2 = REGTAINTEDANY(dst_reg);

  int ids1[8];
  int ids2[8];

  get_mem_taint(addr, REGSIZE(dst_reg), ids1);
  get_reg_taint(dst_reg, ids2);

  if (tainted1 && tainted2)
  {
    process_restrictor_id(ids1, ids2, REGSIZE(dst_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted1)
  {
    process_restrictor_imm(ids1, REGVAL(dst_reg), REGSIZE(dst_reg), type DGB_END_CALL_ARG);
  }
  else if (tainted2)
  {
    process_restrictor_imm(ids2, MEMVAL(addr), REGSIZE(dst_reg), type DGB_END_CALL_ARG);
  }
  else
  {
    invalidate_eflags();
  }

  set_mem_taint(addr, REGSIZE(dst_reg), ids1);
  set_reg_taint(dst_reg, ids2);
}

void nshr_taint_bswap(int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  if (REGTAINTEDANY(dst_reg))
  {
    FAIL();
  }
}

void nshr_taint_strsto_rep(int size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  GET_CONTEXT();

  LDEBUG_TAINT(false, "InsDetail:\tDoing memset of %d bytes.\n", size);

  if (!direction_clear(mcontext.xflags)) FAIL();

  reg_t bytes = reg_get_value(DR_REG_ECX, &mcontext);

  reg_t reg = get_A_of_size(size);

  char *di = (char *) reg_get_value(DR_REG_RDI, &mcontext);
  
  uint64_t daddr = (uint64_t) di;

  memset_reg2mem(reg, daddr, bytes DGB_END_CALL_ARG);
}

// Proceeds before first non-equal or ecx
void nshr_taint_strcmp_rep(int size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  GET_CONTEXT();

  LDEBUG_TAINT(false, "InsDetail:\tDoing strcmp of %d bytes.\n", size);

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

    if (equals == 1)
    {
      update_bounds_strings_equal((uint64_t) si, (uint64_t) di, bytes DGB_END_CALL_ARG);
    }
  }
  else
  {
  	FAIL();
  }
}

void process_shift(int value, int type, int *ids, int *ids2 DBG_END_TAINTING_FUNC)
{
  int amount = (value + 4) / 8;

  // shift left.
  if (type == LOGICAL_LEFT || type == ARITH_LEFT)
  {
    // ids2[i] = ids1[i - amount]
    for (int i = 0; i < 8; i++)
    {
      if (i - amount >= 0)
      {
        ids2[i] = ids[i - amount];
      }
      else
      {
        ids2[i] = -1;
      }
    }  
  }
  else if (type == LOGICAL_RIGHT || type == ARITH_RIGHT)
  {
    // ids2[i] = ids1[i + amount]
    for (int i = 0; i < 8; i++)
    {
      if (i + amount < 8)
      {
        ids2[i] = ids[i + amount];
      }
      else
      {
        ids2[i] = -1;
      }
    }
  }
  else
  {
    FAIL();
  }

  #ifdef LOGDUMP

  char tmp[1024];
  sprintf(tmp, "%d %d %d %d %d %d %d %d ", ids[0], ids[1], ids[2], ids[3],
                                           ids[4], ids[5], ids[6], ids[7]);

  LDUMP_TAINT(0, 0, "Moved by %d bytes, Taints before '%s' shift: %s\n", amount, SHIFT_NAMES[type], tmp);

  sprintf(tmp, "%d %d %d %d %d %d %d %d ", ids2[0], ids2[1], ids2[2], ids2[3], 
                                           ids2[4], ids2[5], ids2[6], ids2[7]);

  LDUMP_TAINT(0, 0, "Taints after shift: %s\n", tmp);

  #endif
}

// Problematic due gcc optimizing divisions by constants to multiplication & shifts.
// This one looks more or less safe, generally very hard to decide when to untaint.
void nshr_taint_shift_regbyimm(int dst_reg, int64 value, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Shifting %s by %d bytes, type %d [1].\n", REGNAME(dst_reg), value, type);

  if (REGTAINTEDANY(dst_reg))
  {
    int ids[8];
    int ids2[8];

    get_reg_taint(dst_reg, ids);

    process_shift(value, type, ids, ids2 DGB_END_CALL_ARG);

    set_reg_taint(dst_reg, ids2);
  }
}

void nshr_taint_shift_regbyreg(int dst_reg, int src_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  // Not sure how to shift by tainted amount.
  if (REGTAINTEDANY(src_reg))
  {
    FAIL();
  }

  GET_CONTEXT();

  int value = reg_get_value(src_reg, &mcontext);

  LDEBUG_TAINT(false, "Shifting %s by %d bytes, type %d [2].\n", REGNAME(dst_reg), value, type);

  if (REGTAINTEDANY(dst_reg))
  {    
    int ids[8];
    int ids2[8];

    get_reg_taint(dst_reg, ids);

    process_shift(value, type, ids, ids2 DGB_END_CALL_ARG);

    set_reg_taint(dst_reg, ids2);
  }
}

void nshr_taint_shift_regbyimm_feedreg(int src_reg, int imm, int feed_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  if (REGTAINTEDANY(src_reg) || REGTAINTEDANY(feed_reg))
  {
    FAIL();
  }
}

void nshr_taint_shift_membyimm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int64 value, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Shifting MEM 0x%llx by %d bytes.\n", addr, value);

  if (MEMTAINTEDANY(addr, access_size))
  {
    int ids[8];
    int ids2[8];

    get_mem_taint(addr, access_size, ids);

    process_shift(value, type, ids, ids2 DGB_END_CALL_ARG);

    set_mem_taint(addr, access_size, ids2);
  }
}

void nshr_taint_shift_membyreg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int src_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Shifting MEM 0x%llx by %s bytes.\n", addr, REGNAME(src_reg));

  if (MEMTAINTEDANY(addr, access_size) || REGTAINTEDANY(src_reg))
  {
    FAIL();
  }
}

void nshr_taint_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2reg(addr, dst_reg DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regzx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2regzx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_mv_mem2regsx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2regsx(addr, dst_reg, extended_from_size DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_reg(int src_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Checking bounds of %s.\n", REGNAME(src_reg));

  check_bounds_reg(src_reg DGB_END_CALL_ARG);
}

void nshr_taint_ind_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  // First, we check if any memory can be referenced (done inside decode_addr)
  // Second, we check if memory that we referenced is (tained || bounded)

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "Checking bounds of MEM 0x%llx.\n", addr);

  check_bounds_mem(addr, size DGB_END_CALL_ARG);
}

static void process_cond_statement(int type, int taken DBG_END_TAINTING_FUNC)
{  
  STOP_IF_NOT_ACTIVE();

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
    /*if (eflags_type != PROP_TEST)
    {
      FAIL();
    }*/
  }

  // This case should be covered by !is_valid_eflags()
  FAILIF(t1 == NULL && t2 == NULL);

  LDUMP_TAINT(0, true, "Updating bounds (taken=%d).\n", taken);

  if (taken) // taken.
  {
    if (t1 != NULL && t2 != NULL)
    {     
      if      (type == COND_LESS)           bound2(t1, t2, COND_LESS);
      else if (type == COND_MORE)           bound2(t2, t1, COND_LESS);
      else if (type == COND_NONZERO)        {} // Gives no info.
      else if (type == COND_ZERO)           bound2(t1, t2, COND_EQ);
      else if (type == COND_LESS_UNSIGNED)  bound2(t1, t2, COND_LESS_UNSIGNED);
      else if (type == COND_MORE_UNSIGNED)  bound2(t2, t1, COND_LESS_UNSIGNED);
      else if (type == COND_SIGN_BIT)       { FAIL(); }
      else if (type == COND_NOT_SIGN_BIT)   { FAIL(); }
      else                                  { FAIL(); }
    }
    else if (t2 == NULL)
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
      if      (type == COND_LESS)           bound2(t2, t1, COND_LESS);
      else if (type == COND_MORE)           bound2(t1, t2, COND_LESS);
      else if (type == COND_NONZERO)        bound2(t1, t2, COND_EQ);
      else if (type == COND_ZERO)           {} // Gives no info
      else if (type == COND_LESS_UNSIGNED)  bound2(t2, t1, COND_LESS_UNSIGNED);
      else if (type == COND_MORE_UNSIGNED)  bound2(t1, t2, COND_LESS_UNSIGNED);
      else if (type == COND_SIGN_BIT)       { FAIL(); }
      else if (type == COND_NOT_SIGN_BIT)   { FAIL(); }
      else                                  { FAIL(); }
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

static void nshr_taint_cond_set_internal(int type, instr_t *instr DBG_END_TAINTING_FUNC)
{
  if (is_valid_eflags())
  {
    GET_CONTEXT();

    int opcode_old = instr_get_opcode(instr);
    
    int opcode = setcc_to_jcc(opcode_old);

    /*
    FIXME: Workaround because DR is missing correct functionality.
    */

    instr_t *newinstr = INSTR_CREATE_jcc_short(drcontext, opcode, opnd_create_pc(0));

    int taken = instr_jcc_taken(newinstr, mcontext.xflags);

    instr_destroy(drcontext, newinstr);

    process_cond_statement(type, taken DGB_END_CALL_ARG);
  }
}

void nshr_taint_cond_set_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int type, instr_t *instr DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDUMP_TAINT(0, true, "Doing conditional set on %llx.\n", addr);

  nshr_taint_cond_set_internal(type, instr DGB_END_CALL_ARG);

  for (int i = 0; i < access_size; i++)
  {
    int index = mem_taint_find_index(addr, i);

    MEMTAINTRM(index, addr + i);
  }
}

void nshr_taint_cond_set_reg(int dst_reg, int type, instr_t *instr DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDUMP_TAINT(0, true, "Doing conditional set on %s.\n", REGNAME(dst_reg));

  nshr_taint_cond_set_internal(type, instr DGB_END_CALL_ARG);

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    REGTAINTRM(dst_reg, i);
  }

  fix_dest_reg(dst_reg);
}

void nshr_taint_cond_jmp(instr_t *instr, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDUMP_TAINT(0, true, "Doing conditional jump by %s.\n", PROP_NAMES[type]);

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
  STOP_IF_NOT_ACTIVE();

  clear_eflags();

  int found = 0;

  LDEBUG_TAINT(false, "Comparing %s with MEM 0x%llx by %s.\n", REGNAME(reg1), addr, PROP_NAMES[type]);

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
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_cmp_reg2constmem(reg1, addr, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_reg2reg(int reg1, int reg2, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Comparing %s with %s by %s.\n", REGNAME(reg1), REGNAME(reg2), PROP_NAMES[type]);

  int found = 0;

  clear_eflags();

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
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Comparing %s with immediate by %s.\n", REGNAME(reg1), PROP_NAMES[type]);

  int found = 0;

  clear_eflags();

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
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_cmp_constmem2reg(addr, size, reg2, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_mem2imm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  nshr_taint_cmp_constmem2imm(addr, size, type DGB_END_CALL_ARG);
}

void nshr_taint_cmp_constmem2reg(uint64_t addr, int size, int reg2, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "Comparing MEM 0x%llx with %s by %s.\n", addr, REGNAME(reg2), PROP_NAMES[type]);

  int found = 0;

  clear_eflags();

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
  STOP_IF_NOT_ACTIVE();

  int found = 0;

  LDEBUG_TAINT(false, "Comparing MEM 0x%llx with immediate by %s.\n", addr, PROP_NAMES[type]);

  clear_eflags();

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
  STOP_IF_NOT_ACTIVE();

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
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

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
  STOP_IF_NOT_ACTIVE();

  GET_CONTEXT();  

  LDEBUG_TAINT(false, "Conditionally moving %s to %s by %s.\n", REGNAME(src_reg), REGNAME(dst_reg), PROP_NAMES[type]);

  int taken = instr_cmovcc_triggered(instr, mcontext.xflags);

  if (is_valid_eflags())
  {
    process_cond_statement(type, taken DGB_END_CALL_ARG);
  }

  if (taken)
  {
    nshr_taint_mv_reg2reg(src_reg, dst_reg DGB_END_CALL_ARG);
  }
}

void nshr_taint_cond_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, instr_t *instr, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  GET_CONTEXT();

  LDEBUG_TAINT(false, "Conditionally moving MEM 0x%llx to %s by %s.\n", 
                        decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG), 
                              REGNAME(dst_reg), PROP_NAMES[type]);
  
  int taken = instr_cmovcc_triggered(instr, mcontext.xflags);

  if (is_valid_eflags())
  {
    process_cond_statement(type, taken DGB_END_CALL_ARG);
  }

  if (taken)
  {
    reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

    nshr_taint_mv_constmem2reg(addr, dst_reg DGB_END_CALL_ARG);
  }
}


static void nshr_taint_internal_neg(int *src_ids, int *dst_ids, unsigned int size DBG_END_TAINTING_FUNC)
{
  for (unsigned int i = 0; i < size; i++)
  {
    if (src_ids[i] > 0)
    {
      int newid = nshr_tid_modify_id_by_symbol(src_ids[i], PROP_NEG, 0);

      LDUMP_TAINT(i, (src_ids[i] > 0 || dst_ids[i] > 0), 
                       "  TAINT#%d index %d NEGATED TO TAINT#%d TOTAL %d.\n", 
                             src_ids[i], i, newid, size);
      dst_ids[i] = newid;
    }
    else
    {
      dst_ids[i] = -1;
    }
  }
}

void nshr_taint_neg_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  LDEBUG_TAINT(false, "NEGATING MEM %p size %d.\n", addr, access_size);

  int ids[8];

  get_mem_taint(addr, access_size, ids);

  nshr_taint_internal_neg(ids, ids, access_size DGB_END_CALL_ARG);

  set_mem_taint(addr, access_size, ids);
}

void nshr_taint_neg_reg(int reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "NEGATING REG %s size %d.\n", REGNAME(reg), REGSIZE(reg));

  int ids[8];

  get_reg_taint(reg, ids);

  nshr_taint_internal_neg(ids, ids, REGSIZE(reg) DGB_END_CALL_ARG);

  set_reg_taint(reg, ids);
}

void nshr_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "REG %s size %d -> REG %s size %d.\n", 
             REGNAME(src_reg), REGSIZE(src_reg), 
                 REGNAME(dst_reg), REGSIZE(dst_reg));


  FAILIF(REGSIZE(src_reg) != REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(src_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, i)), 
                     "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

    REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
  }

  fix_dest_reg(dst_reg);
}

void nshr_taint_mv_reg2regzx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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

  fix_dest_reg(dst_reg);
}


void nshr_taint_mv_regbyte2regsx(int src_reg, int src_index, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "REG %s byte %d copied to whole REG %s size %d.\n", 
             REGNAME(src_reg), src_index, REGNAME(dst_reg), REGSIZE(dst_reg));  

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i) || REGTAINTED(src_reg, src_index)), 
                     "  REG %s byte %d TAINT#%d -> REG %s byte %d TAINT#%d TOTAL %d.\n", 
                           REGNAME(src_reg), src_index, REGTAINTVAL(src_reg, src_index),
                               REGNAME(dst_reg), i,
                                   REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));


     REGTAINTRM(dst_reg, i);
  }

  fix_dest_reg(dst_reg);
}

void nshr_taint_mv_reg2regsx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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
     REGTAINTRM(dst_reg, i);
  }

  fix_dest_reg(dst_reg);
}

// dst_reg = dst_reg+src (or 1, ^, &, depending on type)
void nshr_taint_mix_constmem2reg(uint64 addr, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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

  fix_dest_reg(dst_reg);
}

// dst = dst+src_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

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
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

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

  fix_dest_reg(dst_reg);
}

// dst_reg = src_reg+dst_reg (or 1, ^, &, depending on type)
void nshr_taint_mix_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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
                       REGNAME(src_reg), i, REGTAINTVAL(src_reg, i),
                             REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));


      REGTAINT2REGTAINT(src_reg, i, dst_reg, i);
    }
  }

  fix_dest_reg(dst_reg);
}

void nshr_taint_mv_reg_rm(int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  LDEBUG_TAINT(false, "REMOVE REG %s size %d\n", REGNAME(dst_reg), REGSIZE(dst_reg));

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    LDUMP_TAINT(i, (REGTAINTED(dst_reg, i)), "  REMOVE REG %s byte %d TAINT#%d TOTAL %d.\n", 
                       REGNAME(dst_reg), i, REGTAINTVAL(dst_reg, i), REGSIZE(dst_reg));

    REGTAINTRM(dst_reg, i);
  }

  fix_dest_reg(dst_reg);
}


void nshr_taint_by_file(reg_t addr, unsigned int size, int file)
{
  if (files_history_[file].secure)
  {
    LDEBUG("NOT Tainting %d bytes from %s.\n", size, files_history_[file].path);

    return;
  }

  LDEBUG("ADD MEM %p size %d mark %d\n", addr, size, nshr_tid_new_id_get());

  for (unsigned int i = 0; i < size; i++)
  {
    int index = 0;
  
    while(index < TAINTMAP_NUM && !MEMTAINTISEMPTY(index, addr + i) && (MEMTAINTADDR(index, addr + i) != addr + i))
    {
      index++;
    }
    
    if (index == TAINTMAP_NUM)
    {
      FAIL();
    }
    else
    {
      int newid = nshr_tid_new_uid_by_file(file);
      LDUMP("  ADD MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
                         ADDR(addr + i), newid, index, size);

      SETMEMTAINTVAL(index, addr + i, newid);
    }
  }
}

void nshr_taint_by_fd(reg_t addr, unsigned int size, int fd)
{
  if (fds_history_[fd].secure)
  {
    LDEBUG("NOT Tainting %d bytes from %s.\n", size, fds_history_[fd].path);

    return;
  }

  LDEBUG("ADD MEM %p size %d mark %d\n", addr, size, nshr_tid_new_id_get());

  for (unsigned int i = 0; i < size; i++)
  {
    int index = 0;
  
    while(index < TAINTMAP_NUM && !MEMTAINTISEMPTY(index, addr + i) && (MEMTAINTADDR(index, addr + i) != addr + i))
    {
      index++;
    }
    
    if (index == TAINTMAP_NUM)
    {
      FAIL();
    }
    else
    {
      int newid = nshr_tid_new_uid_by_fd(fd);
      LDUMP("  ADD MEM %p TAINT#%d INDEX %d TOTAL %d.\n", 
      	                 ADDR(addr + i), newid, index, size);

      SETMEMTAINTVAL(index, addr + i, newid);
    }
  }
}

//dst_reg = index_reg + base_reg
void nshr_taint_mv_2coeffregs2reg(int index_reg, int base_reg, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

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

  fix_dest_reg(dst_reg);
}

void print_parse_jump(app_pc pc, char *buffer)
{
  void *handler = hashtable_lookup(&jump_addr_hashtable, pc);

  if (handler == NULL) 
  {
    if (!hashtable_add(&jump_addr_hashtable, pc, (void *)1))
    {
      FAIL();
    }

    module_data_t *data = dr_lookup_module(pc);

    if (data == NULL)
    {
      FAIL();
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
    
    drsym_error_t symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

    if (symres == DRSYM_SUCCESS)
    {
      sprintf(buffer, "in %s[%s] at %s %s:%lu (%p).\n", sym.name, modname, data -> full_path, sym.file, sym.line, pc);
    }
    else
    {
      sprintf(buffer, "in [%s] at %s (%p).\n", modname, data -> full_path, pc);
    }
      
    dr_free_module_data(data);
  }
  else
  {
    sprintf(buffer, "in (%p).\n", pc);
  }
}

static void process_jump(app_pc pc_from, app_pc pc, int is_ret DBG_END_TAINTING_FUNC)
{
  static handleFunc return_from_libc = NULL;

  if ((started_ == MODE_IN_LIBC || started_ == MODE_IN_IGNORELIB) && pc == return_to)
  {
    #ifdef DBG_PARSE_JUMPS

    char str[1024];

    print_parse_jump(pc, str);

    LDUMP_TAINT(0, true, "Returning to Active mode %s", str);

    #else

    LDUMP_TAINT(0, true, "Returning to Active mode\n");

    #endif

    started_ = MODE_ACTIVE;

    // Not preserved through funciton call.

    REGTAINTRMALL(DR_REG_RAX);
    REGTAINTRMALL(DR_REG_RCX);
    REGTAINTRMALL(DR_REG_RDX);

    REGTAINTRMALL(DR_REG_RSI);
    REGTAINTRMALL(DR_REG_RDI);

    REGTAINTRMALL(DR_REG_R8);
    REGTAINTRMALL(DR_REG_R9);
    REGTAINTRMALL(DR_REG_R10);
    REGTAINTRMALL(DR_REG_R11);

    if (return_from_libc != NULL)
    {
      (*return_from_libc)(DGB_END_CALL_ARG_ALONE);
    }

    return;
  }

  if (started_ == MODE_BEFORE_MAIN)
  {
    if (pc == main_address)
    {
      LDEBUG_TAINT(false, "Jumping to main with %d args.\n", get_arg(0));

      const char **argv = (const char **) get_arg(1);

      // Taint all the args.
      for (unsigned int i = 1; i < get_arg(0); i++)
      {
        const char *addr = argv[i];

        nshr_taint_by_fd((uint64_t) addr, strlen(addr), FD_CMD_ARG);
      }
      
      started_ = MODE_ACTIVE;

      return;
    }
  }

  if (started_ != MODE_ACTIVE)
  {
  	return;
  }

  if (pc_from != NULL)
  {
    return_to        = pc_from;
  }

  #ifdef DBG_PARSE_JUMPS

  char str[1024];

  print_parse_jump(pc, str);

  LDUMP_TAINT(0, true, "Detected call %s", str);

  #endif

  if (check_ignore_func(pc))
  {
    LDUMP_TAINT(0, true, "Entered in one of the ignored functions.\n");

    started_ = MODE_IN_IGNORELIB;

    return_from_libc = NULL;

    return;
  }

  handleFunc *handler = hashtable_lookup(&func_hashtable, pc);

  if (handler != NULL) 
  {
    LDUMP_TAINT(0, true, "Goind into MODE_IN_LIBC mode to <%s>.\n", handler[2]);

    // Call pre-funciton.
    if (handler[0] != NULL)
    {
      handler[0](DGB_END_CALL_ARG_ALONE);
    }

    // Register post-function.
    return_from_libc = handler[1];

    started_ = MODE_IN_LIBC;
  }
  else
  {
    module_data_t *data = dr_lookup_module(pc);

    if (data == NULL)
    {
      FAIL();
    }

    const char *modname = dr_module_preferred_name(data);

    if (strcmp(LD_LINUX, modname) == 0 || strcmp(LIBC_NAME, modname) == 0)
    {
      drsym_info_t sym;

      char name_buf[1024];
      char file_buf[1024];

      sym.struct_size = sizeof(sym);
      sym.name = name_buf;
      sym.name_size = 1024;
      sym.file = file_buf;
      sym.file_size = 1024;
    
      // Check if it's known failure.
      drsym_error_t symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

      LDUMP_TAINT(0, true, "Goind into MODE_IN_LIBC mode to '%s'.\n", sym.name);

      if (strcmp(sym.name, "__libc_start_main") != 0 &&
          strcmp(sym.name, "_dl_fini") != 0 &&
          strcmp(sym.name, "msort_with_tmp.part.0") != 0)
      {
        LERROR("ERROR! Failed jumping to %s[%s] at %s  %s:%d.\n", sym.name, modname, data -> full_path, 
                                            sym.file, sym.line);

        return_from_libc = NULL;
      }

      started_ = MODE_IN_LIBC;
    }

    dr_free_module_data(data);
  }
}

void nshr_taint_check_ret(uint64_t pc_from DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t pc_to = *((uint64_t *) reg_get_value(DR_REG_RSP, &mcontext));

  process_jump((byte *) pc_from, (unsigned char *) pc_to, 1 DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_reg(uint64_t pc_from, int reg DBG_END_TAINTING_FUNC)
{
  GET_CONTEXT();
  
  reg_t pc = reg_get_value(reg, &mcontext);

  process_jump((byte *) pc_from, (unsigned char *) pc, 0 DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_mem(uint64_t pc_from, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC)
{
  reg_t addr;

  if (started_ == MODE_ACTIVE)
  {
    addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);
  }
  else
  {
    addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 0 DGB_END_CALL_ARG);
  }

  reg_t pc = *((reg_t *) addr);

  process_jump((byte *) pc_from, (unsigned char *) pc, 0 DGB_END_CALL_ARG);
}

void nshr_taint_check_jmp_immed(uint64_t pc_from, uint64_t pc DBG_END_TAINTING_FUNC)
{
  process_jump((byte *) pc_from, (unsigned char *) pc, 0 DGB_END_CALL_ARG);
}


//dividend / divisor = quotient
void nshr_taint_div_mem(int dividend1_reg, int dividend2_reg, int divisor_seg_reg, int divisor_base_reg, int divisor_index_reg, int divisor_scale, 
                                                 int divisor_disp, int access_size, int quotinent_reg, int remainder_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(divisor_seg_reg, divisor_base_reg, divisor_index_reg, divisor_scale, divisor_disp, 1 DGB_END_CALL_ARG);

  int divident1_tainted = REGTAINTEDANY(dividend1_reg);
  int divident2_tainted = REGTAINTEDANY(dividend2_reg);
  int divisor_tainted   = MEMTAINTEDANY(addr, access_size);

  FAILIF(divident1_tainted);

  FAILIF(REGSIZE(dividend2_reg) != REGSIZE(quotinent_reg));

  nshr_taint_mv_reg2reg(dividend2_reg, quotinent_reg DGB_END_CALL_ARG);

  nshr_taint_mv_reg_rm(remainder_reg DGB_END_CALL_ARG);
}


void nshr_taint_div_reg(int dividend1_reg, int dividend2_reg, int divisor_reg, int quotinent_reg, int remainder_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  int divident1_tainted = REGTAINTEDANY(dividend1_reg);
  int divident2_tainted = REGTAINTEDANY(dividend2_reg);
  int divisor_tainted   = REGTAINTEDANY(divisor_reg);

  FAILIF(divident1_tainted);

  FAILIF(REGSIZE(dividend2_reg) != REGSIZE(quotinent_reg));

  nshr_taint_mv_reg2reg(dividend2_reg, quotinent_reg DGB_END_CALL_ARG);

  nshr_taint_mv_reg_rm(remainder_reg DGB_END_CALL_ARG);
}

void nshr_taint_mul_mem2reg(int src1_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  reg_t addr = decode_addr(seg_reg, base_reg, index_reg, scale, disp, 1 DGB_END_CALL_ARG);

  int src1_tainted = REGTAINTEDANY(src1_reg);
  int src2_tainted = MEMTAINTEDANY(addr, access_size);

  if (!src1_tainted && !src2_tainted)
  {
    REGTAINTRMALL(dst1_reg);

    if (dst2_reg != DR_REG_NULL)
    {
      REGTAINTRMALL(dst2_reg);
    }

    return;  
  }

  if (src1_tainted && src2_tainted)
  {
    int ids1[8];
    int ids2[8];
    
    get_reg_taint(src1_reg, ids1);
    get_mem_taint(addr, access_size, ids2);
  
    int newid = nshr_make_id_by_merging_all_ids(ids1, ids2);

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
      reg_t bytes = MEMVAL(addr);

      nshr_taint_mul_imm2reg(src1_reg, bytes, dst1_reg, DR_REG_NULL DGB_END_CALL_ARG);

      if (dst2_reg != DR_REG_NULL)
      {
        nshr_taint_mul_imm2reg(src1_reg, bytes, dst2_reg, DR_REG_NULL DGB_END_CALL_ARG); 
      }
    }
    else
    {
      reg_t bytes = reg_get_value(src1_reg, &mcontext);

      nshr_taint_mul_immbyconstmem2reg(bytes, addr, access_size, dst1_reg DGB_END_CALL_ARG);

      if (dst2_reg != DR_REG_NULL)
      {
        nshr_taint_mul_immbyconstmem2reg(bytes, addr, access_size, dst2_reg DGB_END_CALL_ARG);
      }
    }
  }

  fix_dest_reg(dst1_reg);

  if (dst2_reg != DR_REG_NULL)
  {
    fix_dest_reg(dst2_reg);
  }
}


void nshr_taint_mul_immbyconstmem2reg(int64 value, uint64_t addr, int access_size, int dst_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  int src1_tainted = MEMTAINTEDANY(value, access_size);

  if (!src1_tainted)
  {
    REGTAINTRMALL(dst_reg);

    return;
  }

  int ids1[8];
  int ids2[8];
    
  get_mem_taint(addr, access_size, ids1);
  get_mem_taint(addr, access_size, ids2);

  // FIXME: Make another function for merging just 1.
  int newid = nshr_make_id_by_merging_all_ids(ids1, ids2);

  if (value < 0)
  {
    newid = nshr_tid_modify_id_by_symbol(newid, PROP_NEG, 0);
  }

  for (unsigned int i = 0; i < REGSIZE(dst_reg); i++)
  {
    SETREGTAINTVAL(dst_reg, i, newid);
  }

  fix_dest_reg(dst_reg);
}

void nshr_taint_mul_reg2reg(int src1_reg, int src2_reg, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  int src1_tainted = REGTAINTEDANY(src1_reg);
  int src2_tainted = REGTAINTEDANY(src2_reg);

  if (!src1_tainted && !src2_tainted)
  {
    REGTAINTRMALL(dst1_reg);

    if (dst2_reg != DR_REG_NULL)
    {
      REGTAINTRMALL(dst2_reg);
    }

    return;
  }

  if (src1_tainted && src2_tainted)
  {

    int ids1[8];
    int ids2[8];
    
    get_reg_taint(src1_reg, ids1);
    get_reg_taint(src2_reg, ids2);
  
    int newid = nshr_make_id_by_merging_all_ids(ids1, ids2);

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

  fix_dest_reg(dst1_reg);

  if (dst2_reg != DR_REG_NULL)
  {
    fix_dest_reg(dst2_reg);
  }
}

// Maybe we can do something more accurate later....
void nshr_taint_mul_imm2reg(int src1_reg, int64 value, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  int src1_tainted = REGTAINTEDANY(src1_reg);

  if (!src1_tainted)
  {
    REGTAINTRMALL(dst1_reg);

    if (dst2_reg != DR_REG_NULL)
    {
      REGTAINTRMALL(dst2_reg);
    }

    return;
  }

  int ids1[8];
  int ids2[8];
    
  get_reg_taint(src1_reg, ids1);
  get_reg_taint(src1_reg, ids2);
  
  int newid = nshr_make_id_by_merging_all_ids(ids1, ids2);

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

  fix_dest_reg(dst1_reg);

  if (dst2_reg != DR_REG_NULL)
  {
    fix_dest_reg(dst2_reg);
  }
}


void nshr_taint_wrong(instr_t *instr DBG_END_TAINTING_FUNC)
{
  STOP_IF_NOT_ACTIVE();

  FAIL();
}