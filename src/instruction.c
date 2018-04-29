#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

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
      LDUMP("InsDetail:\tTaint %s + %d*%s + %d to %s, %d bytes.\n", get_register_name(base_reg), 
                       scale, get_register_name(index_reg), disp, get_register_name(dst_reg), size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_2coeffregs2reg, false, DBG_TAINT_NUM_PARAMS(5),
                               OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(scale), 
                                   OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(disp), 
                                       OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
    }
    else if (index_reg > 0) 
    {

      LDUMP("InsDetail:\tTaint %s to %s, %d bytes.\n", get_register_name(index_reg), 
                       get_register_name(dst_reg), size);

      FAIL();
    }
    else if (base_reg > 0) // dst = base + disp
    {
      LDUMP("InsDetail:\tTaint %s + %d to %s, %d bytes.\n", get_register_name(base_reg), disp,
                       get_register_name(dst_reg), size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_add_val2reg, false, DBG_TAINT_NUM_PARAMS(3),
                               OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(dst_reg), 
                                   OPND_CREATE_INT64(disp) DBG_END_DR_CLEANCALL);
    }
  }
  else if (opnd_is_rel_addr(src))
  {
    LDUMP("InsDetail:\tRemove taint at %s, %d bytes\n", get_register_name(dst_reg), size);

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                             OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
  }
  else
  {
  	FAIL();
  }
}

static void propagate(void *drcontext, instr_t *instr, instrlist_t *ilist, opnd_t src, opnd_t dst, enum prop_type type)
{
  // src: base+index
  if (opnd_is_base_disp(src))
  {
    reg_id_t base_reg  = opnd_get_base(src);
    reg_id_t index_reg = opnd_get_index(src);
    reg_id_t seg_reg   = opnd_get_segment(src);
    int scale          = opnd_get_scale(src);
    int disp           = opnd_get_disp(src);

    if (opnd_is_reg(dst))
    {
      /*
          base+index to register.
      */
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      if (is_mov(type))
      {
        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s %d bytes.\n", 
                                           get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                                get_register_name(index_reg), disp, regname, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2reg, false, DBG_TAINT_NUM_PARAMS(6),
                             OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                               OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg),
                                 OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      /*
      else if (type == PROP_MOVZX)
      {
        int dstsize = size;
        int srcsize = opnd_size_in_bytes(opnd_get_size(src));

        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s zero extend %d bytes to %d bytes.\n", 
                                           get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                                get_register_name(index_reg), disp, regname, srcsize, dstsize);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2regzx, false, DBG_TAINT_NUM_PARAMS(7),
                             OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                               OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg),
                                 OPND_CREATE_INT32(dst_reg), OPND_CREATE_INT32(srcsize) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVSX)
      {
        int dstsize = size;
        int srcsize = opnd_size_in_bytes(opnd_get_size(src));

        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s sign extend %d bytes to %d bytes.\n", 
                                           get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                                get_register_name(index_reg), disp, regname, srcsize, dstsize);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2regsx, false, DBG_TAINT_NUM_PARAMS(7),
                             OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                               OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg),
                                 OPND_CREATE_INT32(dst_reg), OPND_CREATE_INT32(srcsize) DBG_END_DR_CLEANCALL);
      }
      */
    }
    else
    {
      FAIL();
    }
  }
  // src: immediate.
  else if (opnd_is_immed(src))
  {
    if (opnd_is_reg(dst))
    {
      /*
          immediate to register.
      */
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      if (type == PROP_MOV)
      {
        LDUMP("InsDetail:\tRemove taint at %s, %d bytes\n", regname, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                                 OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else
      {
        int64 value = opnd_get_immed_int(src);

        LDUMP("InsDetail:\tDoing '%s' to taint at %s, by 0x%x, %d bytes\n", PROP_NAMES[type], 
        	             regname, value, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_val2reg, false, DBG_TAINT_NUM_PARAMS(4),
                                 OPND_CREATE_INT32(dst_reg), OPND_CREATE_INT32(dst_reg), 
                                     OPND_CREATE_INT64(value), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);

      }
    }
    else if (opnd_is_base_disp(dst))
    {
      /*
          immediate to base+index.
      */
      reg_id_t base_reg  = opnd_get_base(dst);
      reg_id_t index_reg = opnd_get_index(dst);
      reg_id_t seg_reg   = opnd_get_segment(dst);
      int scale          = opnd_get_scale(dst);
      int disp           = opnd_get_disp(dst);

      int size = opnd_size_in_bytes(opnd_get_size(src));

      if (seg_reg == DR_REG_NULL)
      {
        LDUMP("InsDetail:\tRemove taint at base+disp %s: %s + %d*%s + %d, %d bytes.\n",
                                   get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                       get_register_name(index_reg), disp, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_baseindexmem_rm, false, DBG_TAINT_NUM_PARAMS(6), 
                            OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(scale), 
                               OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(size) DBG_END_DR_CLEANCALL);
      }
      else if (seg_reg != DR_SEG_FS && seg_reg != DR_SEG_GS)
      {
        // Temporarily ignore all memory accesses in FS and GS segments.
      	FAIL();
      }
    }
    else if (opnd_is_rel_addr(dst))
    {
      /*
          immediate to relative memory.
      */
      app_pc addr;

      instr_get_rel_addr_target(instr, &addr);

      int size = opnd_size_in_bytes(opnd_get_size(src));

      LDUMP("InsDetail:\tRemove taint at pc-relative %llx, %d bytes.\n", 
                                      addr, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem_rm, false, DBG_TAINT_NUM_PARAMS(2), 
                               OPND_CREATE_INT64(addr), OPND_CREATE_INT32(size) DBG_END_DR_CLEANCALL);
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

    if (opnd_is_base_disp(dst))
    {
      /*
          register to base+index.
      */
      reg_id_t base_reg  = opnd_get_base(dst);
      reg_id_t index_reg = opnd_get_index(dst);
      reg_id_t seg_reg   = opnd_get_segment(dst);
      int scale          = opnd_get_scale(dst);
      int disp           = opnd_get_disp(dst);

      LDUMP("InsDetail:\tTaint %s to base+disp %s: %s + %d*%s + %d, %d bytes.\n", 
                                      regname, get_register_name(seg_reg), get_register_name(base_reg), scale, 
                                          get_register_name(index_reg), disp, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2mem, false, DBG_TAINT_NUM_PARAMS(6), 
                       OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(src_reg), OPND_CREATE_INT32(disp), 
                            OPND_CREATE_INT32(scale), OPND_CREATE_INT32(base_reg),  OPND_CREATE_INT32(index_reg) DBG_END_DR_CLEANCALL);
    }
    else if (opnd_is_reg(dst))
    {
      /*
          register to register.
      */
      reg_id_t dst_reg = opnd_get_reg(dst);

      const char *regname2 = get_register_name(dst_reg);

      UNUSED(regname2);

      if(type == PROP_XOR && src_reg == dst_reg)
      {
        LDUMP("InsDetail:\tRemoving taint from %s.\n", regname);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                             OPND_CREATE_INT32(src_reg) DBG_END_DR_CLEANCALL);
      }
      else if (is_binary(type))
      {
        LDUMP("InsDetail:\tDoing '%s' to taint at %s, to %s, %d bytes\n", PROP_NAMES[type], 
        	             regname, regname2, size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_reg2reg, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT32(dst_reg), OPND_CREATE_INT32(src_reg),
                                     OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
      }
      else
      {
        LDUMP("InsDetail:\tTaint %s to %s.\n", regname, regname2);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(src_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
    }
    else if (opnd_is_rel_addr(dst))
    {
      /*
          register to relative memory.
      */
      app_pc addr;

      instr_get_rel_addr_target(instr, &addr);

      LDUMP("InsDetail:\tTaint %s to pc-relative %llx, %d bytes.\n", 
                                      regname, addr, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2constmem, false, DBG_TAINT_NUM_PARAMS(2), 
                               OPND_CREATE_INT32(src_reg), OPND_CREATE_INT64(addr) DBG_END_DR_CLEANCALL);
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

    if (opnd_is_reg(dst))
    {
      /*
          relative memory to register.
      */
      const char *regname = get_register_name(opnd_get_reg(dst));
      int size            = opnd_size_in_bytes(reg_get_size(opnd_get_reg(dst)));

      reg_id_t dst_reg = opnd_get_reg(dst);

      UNUSED(regname);
      UNUSED(size);

      LDUMP("InsDetail:\tTaint from pc-relative %llx to %s %d bytes.\n", addr, regname, size);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_constmem2reg, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT64(addr), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
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

  //LDEBUG("AAAAAAAAA src: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(src), 
  //                                      opnd_is_immed(src),  opnd_is_base_disp(src),  opnd_is_mem_instr(src), opnd_is_rel_addr(src));
  //LDEBUG("AAAAAAAAA dst: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(dst), 
  //                                     opnd_is_immed(dst),  opnd_is_base_disp(dst),  opnd_is_mem_instr(dst), opnd_is_rel_addr(dst));

  propagate(drcontext, instr, ilist, src, dst, PROP_MOV);
}

static void opcode_movzx(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src = instr_get_src(instr, 0);
  opnd_t dst = instr_get_dst(instr, 0);

  propagate(drcontext, instr, ilist, src, dst, PROP_MOVZX);
}

static void opcode_movsx(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src = instr_get_src(instr, 0);
  opnd_t dst = instr_get_dst(instr, 0);

  propagate(drcontext, instr, ilist, src, dst, PROP_MOVSX);
}


// src2 == dst
static void opcode_add(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src1 = instr_get_src(instr, 0);
  opnd_t src2 = instr_get_src(instr, 1);
  opnd_t dst  = instr_get_dst(instr, 0);

  if (memcmp((void *) &src2, (void *) &dst, sizeof(opnd_t)) != 0) {  FAIL(); }

  int opcode = instr_get_opcode(instr);

  if (opcode == OP_sub)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_SUB);
  }
  else if (opcode == OP_add)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_ADD);
  }
  else if (opcode == OP_or)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_OR);
  }
  else if (opcode == OP_adc)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_ADC);
  }
  else if (opcode == OP_sbb)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_SBB);
  }
  else if (opcode == OP_and)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_AND);
  }
  else if (opcode == OP_xor)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_XOR);
  }
  else if (opcode == OP_imul)
  {
    propagate(drcontext, instr, ilist, src1, dst, PROP_IMUL);
  }

}

static void opcode_ignore(void *drcontext, instr_t *instr, instrlist_t *ilist)
{

}

static void wrong_opcode(void *drcontext, instr_t *instr, instrlist_t *ilist)
{ 
//  LERROR("ERROR! instruction not implemented.\n");

//  FAIL();
}

static void opcode_call(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  if (!instr_is_cti(instr)) FAIL();

  app_pc pc;

  opnd_t t = instr_get_target(instr);

  if (opnd_is_pc(t))
  {
     pc = opnd_get_pc(t);

     return;
  }
  else if (opnd_is_rel_addr(t))
  {
  	app_pc tmp;

    instr_get_rel_addr_target(instr, &tmp);

    pc = (app_pc) (*(uint64 *) tmp);

    return;
  }
  else if (opnd_is_reg(t))
  {
  	if (opnd_get_reg(t) == DR_REG_RSP)
  	{
      //dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_ret, false, 0);
  	}
  	else
  	{
  	  return;
      //dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_ret, false, 1,
      //                       OPND_CREATE_INT32(ENCODE_REG(opnd_get_reg(t))));
  	}
  }
  else if (opnd_is_base_disp(t))
  {
  	return;
  }
  else
  {
  	FAIL();
  }

  return;

/*
  module_data_t *data = dr_lookup_module(pc);

  if (data == NULL)
  {
     LDUMP("InsDetail:\tIgnoring jump to %llx.\n", pc);

     dr_free_module_data(data);

     return;
  }

  const char *modname = dr_module_preferred_name(data);

  dr_printf("Performing jump to %s.\n", modname);

  // DON'T FORGET IT!
  dr_free_module_data(data);

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
  	LDUMP("InsDetail:\tDetected call to %s[%s] at %s.\n", sym.name, modname, data -> full_path);
  }
  else
  {
  	LDUMP("InsDetail:\tMissing symbols for call to [%s] at %s.\n", modname, data -> full_path);
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

  instrFunctions[OP_add]			= opcode_add;   //4

  instrFunctions[OP_and]			= opcode_add;   //8

  instrFunctions[OP_sub]			= opcode_add;   //10

  instrFunctions[OP_xor]			= opcode_add;   //12

  instrFunctions[OP_imul]			= opcode_add;

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

  //instrFunctions[OP_ret]			= opcode_call;		// 70

  instrFunctions[OP_syscall]		= opcode_ignore;	// 95 syscall processed by dr_register_post_syscall_event.

  instrFunctions[OP_movzx]          = opcode_movzx;     // 195

  instrFunctions[OP_movsx]          = opcode_movsx;     // 200

  instrFunctions[OP_movsxd]         = opcode_movsx;     // 597
}

//
// Called for each added basic block.
//

dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace,
                                bool translating, void *user_data)
{
  STOP_IF_IGNORING(DR_EMIT_DEFAULT);

  char instruction[64];

  int opcode = instr_get_opcode(instr);

  if (started_ == MODE_ACTIVE || 
  	     (started_ == MODE_IN_LIBC && opcode == OP_ret))
  {
    instr_disassemble_to_buffer(drcontext, instr, instruction, 64);

    if (started_ == MODE_ACTIVE)
    {
      LDEBUG("\t\t(opcode %d)\t%s.\n", opcode, instruction);
    }

    (*instrFunctions[opcode])(drcontext, instr, bb);
  }

  return DR_EMIT_DEFAULT;
}


