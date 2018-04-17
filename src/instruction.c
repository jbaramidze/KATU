#define DUMP_INSTRUCTIONS
#define DUMP_INSTRUCTION_DETAILS

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"
#include "drsyms.h"

#include <string.h>

/*
  Helpful functions:
    instr_get_src, instr_num_srcs, opnd_is_immed, instr_reads_memory, opnd_is_reg, opnd_is_immed,
    typedef uint64 reg_t

*/

// for each register, specify where to start tainting from, according our table
static const int reg_mask_start[69] = { 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4,
                                 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6,
                                 0x7, 0x7, 0x7, 0x7, 0x6, 0x6, 0x6, 0x6, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7,
                                 0x7, 0x7, 0x7, 0x7 };

static const int reg_mask_index[69] =  {0,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   0,   1,   2,   3,   8,   9,   10,  11,  12,  13,  14,  15,
                                 4,   5,   6,   7   };


static void opcode_lea(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src = instr_get_src(instr, 0);
  opnd_t dst = instr_get_dst(instr, 0);

  if (!opnd_is_reg(dst))
  {
  	FAIL();
  }

  reg_id_t dst_reg   = opnd_get_reg(dst);
  int size            = opnd_size_in_bytes(reg_get_size(dst_reg));

  if (opnd_is_base_disp(src))
  {
    reg_id_t base_reg  = opnd_get_base(src);
    reg_id_t index_reg = opnd_get_index(src);
    int scale          = opnd_get_scale(src);
    int disp           = opnd_get_disp(src);
    

    UNUSED(size);

    if (base_reg > 0 && index_reg > 0)
    {
      LINSTRDETAIL("InsDetail:\tTaint from %s + %d*%s + %d to %s, %d bytes.\n", get_register_name(base_reg), 
                       scale, get_register_name(index_reg), disp, get_register_name(dst_reg), size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_2coeffregs2reg, false, 4,
                               OPND_CREATE_INT32(ENCODE_REG(index_reg)), OPND_CREATE_INT32(scale), 
                                   OPND_CREATE_INT32(ENCODE_REG(base_reg)), OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
    else if (index_reg > 0) 
    {

      LINSTRDETAIL("InsDetail:\tTaint from %s to %s, %d bytes.\n", get_register_name(index_reg), 
                       get_register_name(dst_reg), size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, 2,
                               OPND_CREATE_INT32(ENCODE_REG(index_reg)), OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
    else if (base_reg > 0)
    {

      LINSTRDETAIL("InsDetail:\tTaint from %s to %s, %d bytes.\n", get_register_name(base_reg), 
                       get_register_name(dst_reg), size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, 2,
                               OPND_CREATE_INT32(ENCODE_REG(base_reg)), OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
  }
  else if (opnd_is_rel_addr(src))
  {
    LINSTRDETAIL("InsDetail:\tRemove taint at %s, %d bytes\n", get_register_name(dst_reg), size);

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, 1,
                             OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
  }
  else
  {
  	FAIL();
  }
}

static void propagate(void *drcontext, instr_t *instr, instrlist_t *ilist, opnd_t src, opnd_t dst)
{
  // src: base+index
  if (opnd_is_base_disp(src))
  {
    reg_id_t base_reg  = opnd_get_base(src);
    reg_id_t index_reg = opnd_get_index(src);
    reg_id_t seg_reg   = opnd_get_segment(src);
    int scale          = opnd_get_scale(src);
    int disp           = opnd_get_disp(src);

    // base+index to reg
    if (opnd_is_reg(dst))
    {
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      LINSTRDETAIL("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s %d bytes.\n", 
                                         get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                              get_register_name(index_reg), disp, regname, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2reg, false, 6,
                           OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                             OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg),
                               OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
    else
    {
      FAIL();
    }
  }
  // src: immediate.
  else if (opnd_is_immed(src))
  {
    // immediate to reg
    if (opnd_is_reg(dst))
    {
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      LINSTRDETAIL("InsDetail:\tRemove taint at %s, %d bytes\n", regname, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, 1,
                               OPND_CREATE_INT32(ENCODE_REG(dst_reg)));

    }
    // immediate to base+index
    else if (opnd_is_base_disp(dst))
    {
      reg_id_t base_reg  = opnd_get_base(dst);
      reg_id_t index_reg = opnd_get_index(dst);
      reg_id_t seg_reg   = opnd_get_segment(dst);
      int scale          = opnd_get_scale(dst);
      int disp           = opnd_get_disp(dst);

      int size = opnd_size_in_bytes(opnd_get_size(src));

      if (seg_reg == DR_REG_NULL)
      {
        LINSTRDETAIL("InsDetail:\tRemove taint at base+disp %s: %s + %d*%s + %d, %d bytes.\n",
                                   get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                       get_register_name(index_reg), disp, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_baseindexmem_rm, false, 6, 
                            OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                               OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(size));
      }
      else if (seg_reg != DR_SEG_FS && seg_reg != DR_SEG_GS)
      {
        // Temporarily ignore all memory accesses in FS and GS segments.
      	FAIL();
      }
    }
    // immediate to rel addr
    else if (opnd_is_rel_addr(dst))
    {
      app_pc addr;

      instr_get_rel_addr_target(instr, &addr);

      int size = opnd_size_in_bytes(opnd_get_size(src));

      LINSTRDETAIL("InsDetail:\tRemove taint at pc-relative %llx, %d bytes.\n", 
                                      addr, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem_rm, false, 2, 
                               OPND_CREATE_INT64(addr), OPND_CREATE_INT32(size));
    }
    else
    {
      FAIL();
    }
  }
  // src: reg.
  else if (opnd_is_reg(src))
  {
    const char *regname = get_register_name(opnd_get_reg(src));
    int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(src)));

    reg_id_t src_reg = opnd_get_reg(src);

    UNUSED(regname);
    UNUSED(size);

    // reg to base+disp
    if (opnd_is_base_disp(dst))
    {
      reg_id_t base_reg  = opnd_get_base(dst);
      reg_id_t index_reg = opnd_get_index(dst);
      reg_id_t seg_reg   = opnd_get_segment(dst);
      int scale          = opnd_get_scale(dst);
      int disp           = opnd_get_disp(dst);

      LINSTRDETAIL("InsDetail:\tTaint %s to base+disp %s: %s + %d*%s + %d, %d bytes.\n", 
                                      regname, get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                          get_register_name(index_reg), disp, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2mem, false, 6, 
                       OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(ENCODE_REG(src_reg)), OPND_CREATE_INT32(disp), 
                            OPND_CREATE_INT32(scale), OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg));
    }
    // reg to reg
    else if (opnd_is_reg(dst))
    {

      reg_id_t dst_reg = opnd_get_reg(dst);
      const char *regname2 = get_register_name(dst_reg);

      UNUSED(regname2);

      LINSTRDETAIL("InsDetail:\tTaint %s to %s.\n", regname, regname2);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, 2,
                             OPND_CREATE_INT32(ENCODE_REG(src_reg)), OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
    // reg to rel addr
    else if (opnd_is_rel_addr(dst))
    {
      app_pc addr;

      instr_get_rel_addr_target(instr, &addr);

      LINSTRDETAIL("InsDetail:\tTaint %s to pc-relative %llx, %d bytes.\n", 
                                      regname, addr, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2constmem, false, 2, 
                               OPND_CREATE_INT32(ENCODE_REG(src_reg)), OPND_CREATE_INT64(addr));
    }
    else
    {
      FAIL();
    }
  }
  // src: rel addr.
  else if (opnd_is_rel_addr(src))
  {
    app_pc addr;

    instr_get_rel_addr_target(instr, &addr);

    // rel addr to reg
    if (opnd_is_reg(dst))
    {
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      LINSTRDETAIL("InsDetail:\tTaint from pc-relative %llx to %s %d bytes.\n", addr, regname, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_constmem2reg, false, 2,
                               OPND_CREATE_INT64(addr), OPND_CREATE_INT32(ENCODE_REG(dst_reg)));
    }
    else
    {
      FAIL();
    }
  }
  else
  {
  	FAIL();
  }
}


static void opcode_mov(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src = instr_get_src(instr, 0);
  opnd_t dst = instr_get_dst(instr, 0);

  //LINSTR("AAAAAAAAA src: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(src), 
  //                                      opnd_is_immed(src),  opnd_is_base_disp(src),  opnd_is_mem_instr(src), opnd_is_rel_addr(src));
  //LINSTR("AAAAAAAAA dst: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(dst), 
  //                                     opnd_is_immed(dst),  opnd_is_base_disp(dst),  opnd_is_mem_instr(dst), opnd_is_rel_addr(dst));

  propagate(drcontext, instr, ilist, src, dst);
}


// src2 == dst
static void opcode_add(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src1 = instr_get_src(instr, 0);
  opnd_t src2 = instr_get_src(instr, 1);
  opnd_t dst  = instr_get_dst(instr, 0);

  if (memcmp((void *) &src2, (void *) &dst, sizeof(opnd_t)) != 0) {  FAIL(); }

  propagate(drcontext, instr, ilist, src1, dst);

}


static void opcode_ignore(void *drcontext, instr_t *instr, instrlist_t *ilist)
{

}

static void wrong_opcode(void *drcontext, instr_t *instr, instrlist_t *ilist)
{ 
  LERROR("ERROR! instruction not implemented.\n");

  FAIL();
}

static void opcode_call(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
/*
  if (!instr_is_cti(instr)) FAIL();

  app_pc pc;

  opnd_t t = instr_get_target(instr);

  if (opnd_is_pc(t))
  {
     pc = opnd_get_pc(t);
  }
  else if (opnd_is_rel_addr(t))
  {
  	app_pc tmp;

    instr_get_rel_addr_target(instr, &tmp);

    pc = (app_pc) (*(uint64 *) tmp);
  }
  else
  {
  	FAIL();
  }

  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
     LINSTRDETAIL("InsDetail:\tIgnoring jump to %llx.\n", pc);

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
  sym.file_size = 0;

  drsym_error_t symres;

  symres = drsym_lookup_address(data -> full_path, pc - data -> start, &sym, DRSYM_DEFAULT_FLAGS);

  if (symres == DRSYM_SUCCESS)
  {
  	LINSTRDETAIL("InsDetail:\tDetected call to %s[%s] at %s.\n", sym.name, modname, data -> full_path);
  }
  else
  {
  	LINSTRDETAIL("InsDetail:\tMissing symbols for call to [%s] at %s.\n", modname, data -> full_path);
  }
  */
}


void nshr_init_opcodes(void)
{
  for (int i = 0; i < MAX_OPCODE; i++)
  {
    instrFunctions[i] = wrong_opcode;
  }

  //
  // Add custom handlers for all known opcodes.
  //

  instrFunctions[OP_sub]			= opcode_add;   //10

  instrFunctions[OP_call]			= opcode_call;	// 42
  instrFunctions[OP_call_ind]		= opcode_call;	// 43
  instrFunctions[OP_call_far]		= opcode_call;	// 44
  instrFunctions[OP_call_far_ind]	= opcode_call;	// 45
  instrFunctions[OP_jmp]			= opcode_call;  // 46
  instrFunctions[OP_jmp_short]		= opcode_call;  // 47
  instrFunctions[OP_jmp_ind]		= opcode_call;  // 48
  instrFunctions[OP_jmp_far]		= opcode_call;  // 49
  instrFunctions[OP_jmp_far_ind]	= opcode_call;  // 50

  instrFunctions[OP_mov_ld]			= opcode_mov;		// 55	Can be: mem2reg
  instrFunctions[OP_mov_st]			= opcode_mov;		// 56	Can be: imm2mem, reg2mem, reg2reg.
  instrFunctions[OP_mov_imm]		= opcode_mov;		// 57   Can be: imm2reg.
// instrFunctions[OP_mov_seg]							// 58
// instrFunctions[OP_mov_priv]							// 59
  instrFunctions[OP_test]			= opcode_ignore;	// 60 
  instrFunctions[OP_lea]			= opcode_lea;		// 61

  instrFunctions[OP_syscall]		= opcode_ignore;	// 95 syscall processed by dr_register_post_syscall_event.
}

//
// Called for each added basic block.
//

dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace,
                                bool translating, void *user_data)
{
  STOP_IF_NOT_STARTED(DR_EMIT_DEFAULT);

  char instruction[64];

  int opcode = instr_get_opcode(instr);

  instr_disassemble_to_buffer(drcontext, instr, instruction, 64);
    
  LINSTR("\t\t(opcode %d)\t%s.\n", opcode, instruction);

  (*instrFunctions[opcode])(drcontext, instr, bb);

  return DR_EMIT_DEFAULT;
}


