#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"

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

  if (opnd_is_base_disp(src))
  {
    reg_id_t base_reg  = opnd_get_base(src);
    reg_id_t index_reg = opnd_get_index(src);
    int scale          = opnd_get_scale(src);
    int disp           = opnd_get_disp(src);

    if (base_reg > 0 && index_reg > 0)
    {
      LDUMP("InsDetail:\tTaint %s + %d*%s + %d to %s, %d bytes.\n", REGNAME(base_reg), 
                       scale, REGNAME(index_reg), disp, REGNAME(dst_reg), REGSIZE(dst_reg));

      if (scale == 0)
      {
      	FAIL();
      }

      if (base_reg == index_reg)
      {
        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2regzx, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else
      {
        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_2coeffregs2reg, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(base_reg),
                                        OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
    }
    else if (index_reg > 0 && scale > 0) 
    {

      LDUMP("InsDetail:\tTaint %s to %s, %d bytes.\n", REGNAME(index_reg), 
                       REGNAME(dst_reg), REGSIZE(dst_reg));

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2regzx, false, DBG_TAINT_NUM_PARAMS(2),
                             OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
    }
    else if (base_reg > 0) // dst = base + disp
    {
      LDUMP("InsDetail:\tTaint %s + %d to %s, %d bytes.\n", REGNAME(base_reg), disp,
                       REGNAME(dst_reg), REGSIZE(dst_reg));


      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2regzx, false, DBG_TAINT_NUM_PARAMS(2),
                             OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
    }
    else
    {
      FAIL();
    }
  }
  else if (opnd_is_rel_addr(src))
  {
    LDUMP("InsDetail:\tRemove taint at %s, %d bytes\n", REGNAME(dst_reg), REGSIZE(dst_reg));

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                             OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
  }
  else
  {
  	FAIL();
  }
}

static void propagate(void *drcontext, instr_t *instr, instrlist_t *ilist, 
	                      opnd_t src1, opnd_t src2, opnd_t dst, enum prop_type type)
{
  // src: base+index
  if (opnd_is_base_disp(src1))
  {
    reg_id_t base_reg  = opnd_get_base(src1);
    reg_id_t index_reg = opnd_get_index(src1);
    reg_id_t seg_reg   = opnd_get_segment(src1);
    int scale          = opnd_get_scale(src1);
    int disp           = opnd_get_disp(src1);

    int extend_from = opnd_size_in_bytes(opnd_get_size(src1));

    if (opnd_is_reg(dst))
    {
      /*
          base+index to register.
      */

      reg_id_t dst_reg = opnd_get_reg(dst);

      if (type == PROP_MOV)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s %d bytes.\n", 
                                           REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                                REGNAME(index_reg), disp, REGNAME(dst_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2reg, false, DBG_TAINT_NUM_PARAMS(6),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale),  OPND_CREATE_INT32(disp), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVZX)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s zero extend %d bytes to %d bytes.\n", 
                                           REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                                REGNAME(index_reg), disp, REGNAME(dst_reg), extend_from, REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2regzx, false, DBG_TAINT_NUM_PARAMS(7),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(dst_reg), 
                                         OPND_CREATE_INT32(extend_from) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVSX)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s sign extend %d bytes to %d bytes.\n", 
                                           REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                                REGNAME(index_reg), disp, REGNAME(dst_reg), extend_from, REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2regsx, false, DBG_TAINT_NUM_PARAMS(7),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(dst_reg), 
                                         OPND_CREATE_INT32(extend_from) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      {
      	if (opnd_is_reg(src2))
      	{
          reg_id_t src2_reg = opnd_get_reg(src2);

          LDUMP("InsDetail:\tDoing '%s' to taint from base+disp %s:%s + %d*%s + %d and %s -> %s %d bytes.\n", PROP_NAMES[type], 
        	        REGNAME(seg_reg), REGNAME(base_reg), scale, REGNAME(index_reg), disp, 
                        REGNAME(src2_reg), REGNAME(dst_reg), REGSIZE(dst_reg));

          dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_memNreg2reg, false, DBG_TAINT_NUM_PARAMS(8),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                        OPND_CREATE_INT32(scale),  OPND_CREATE_INT32(disp), OPND_CREATE_INT32(src2_reg),
                                            OPND_CREATE_INT32(dst_reg), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
        }
        else
        {
          FAIL(); // FIXME: fix for imul 3-operand, third will be immediate, will fail here.
        }
      }
      else if (prop_is_restrictor(type))
      {
      	//FIXME: implement it.
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
  // src: immediate.
  else if (opnd_is_immed(src1))
  {
    if (opnd_is_reg(dst))
    {
      /*
          immediate to register.
      */

      reg_id_t dst_reg = opnd_get_reg(dst);

      if (prop_is_mov(type))
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tRemove taint at %s, %d bytes\n", REGNAME(dst_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                                 OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      {
      	if (opnd_is_reg(src2))
      	{
      	  if (!opnd_same(src2, dst)) {  FAIL(); } // if it fails implement, but hope it's never used.
      	}
      	else
      	{
      		FAIL();
      	}
        // Nothing to do in this case.
      }
      else if (prop_is_restrictor(type))
      {
      	/*
      	FIXME: what if e.g AND 00000011000 was done? it can be limiting. Fix later.
      	*/
        int64 value = opnd_get_immed_int(src1);

        LDUMP("InsDetail:\tDoing '%s' to taint at %s, by 0x%x, %d bytes\n", PROP_NAMES[type], 
        	             REGNAME(dst_reg), value, REGSIZE(dst_reg));
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

      int access_size = opnd_size_in_bytes(opnd_get_size(src1));

      if (prop_is_mov(type))
      { 
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        if (seg_reg == DR_REG_NULL)
        {
          LDUMP("InsDetail:\tRemove taint at base+disp %s: %s + %d*%s + %d, %d bytes.\n",
                                     REGNAME(seg_reg), REGNAME(base_reg), scale, REGNAME(index_reg), disp, access_size);

          dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_baseindexmem_rm, false, DBG_TAINT_NUM_PARAMS(6),
        	                       OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                       OPND_CREATE_INT32(scale), OPND_CREATE_INT32(disp), 
                                           OPND_CREATE_INT32(access_size) DBG_END_DR_CLEANCALL);
        }
        else if (seg_reg != DR_SEG_FS && seg_reg != DR_SEG_GS)
        {
          // Temporarily ignore all memory accesses in FS and GS seg_regs.
        	FAIL();
        }
      }
      else if (prop_is_binary(type))
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        // Nothing to do in this case.
      }
      else if (prop_is_restrictor(type))
      {
      	/*
      	FIXME: what if e.g AND 00000011000 was done? it can be limiting. Fix later.
      	*/
        int64 value = opnd_get_immed_int(src1);

        LDUMP("InsDetail:\tDoing '%s' to taint at base+disp %s: %s + %d*%s + %d, by 0x%x, %d bytes\n", 
                  PROP_NAMES[type], REGNAME(seg_reg), REGNAME(base_reg), scale, REGNAME(index_reg), disp,
                         value, access_size);
      }
      else
      {
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

      int access_size = opnd_size_in_bytes(opnd_get_size(src1));

      if (prop_is_mov(type))
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tRemove taint at pc-relative %llx, %d bytes.\n", addr, access_size);

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem_rm, false, DBG_TAINT_NUM_PARAMS(2), 
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(access_size) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

      	// Nothing to do in this case.
      }
      else if (prop_is_restrictor(type))
      {      	
        /*
      	FIXME: what if e.g AND 00000011000 was done? it can be limiting. Fix later.
      	*/
        int64 value = opnd_get_immed_int(src1);

        LDUMP("InsDetail:\tDoing '%s' to taint at pc-relative %llx, by 0x%x, %d bytes\n", 
                  PROP_NAMES[type], addr, value, access_size);
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
  // src: reg.
  else if (opnd_is_reg(src1))
  {
    reg_id_t src1_reg = opnd_get_reg(src1);

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

      if (type == PROP_MOV)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from %s to base+disp %s: %s + %d*%s + %d, %d bytes.\n", 
                                        REGNAME(src1_reg), REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                            REGNAME(index_reg), disp, REGSIZE(src1_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2mem, false, DBG_TAINT_NUM_PARAMS(6), 
                                 OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), 
                                     OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(scale), 
                                         OPND_CREATE_INT32(disp) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      { 
      	if (opnd_is_base_disp(src2))
      	{
      	  // make sure it's the same:
          if (opnd_get_base(src2)    != base_reg) FAIL();
          if (opnd_get_index(src2)   != index_reg) FAIL();
          if (opnd_get_segment(src2) != seg_reg) FAIL();
          if (opnd_get_scale(src2)   != scale) FAIL();
          if (opnd_get_disp(src2)    != disp) FAIL();

      	  LDUMP("InsDetail:\tDoing '%s' to taint from %s and base+disp %s:%s + %d*%s + %d to same mem., %d bytes.\n", PROP_NAMES[type], 
          	                      REGNAME(src1_reg), REGNAME(seg_reg), REGNAME(base_reg), scale, REGNAME(index_reg), 
          	                           disp, REGSIZE(src1_reg));

          dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_reg2mem, false, DBG_TAINT_NUM_PARAMS(7),
                                   OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), 
                                       OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(scale), 
                                           OPND_CREATE_INT32(disp), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
        }
        else
        {
          FAIL();
        }
      }
      else if (prop_is_restrictor(type))
      {
      	//FIXME: implement it.
      }
      else
      {
      	FAIL();
      }
    }
    else if (opnd_is_reg(dst))
    {
      /*
          register to register.
      */
      reg_id_t dst_reg = opnd_get_reg(dst);

      // SPECIALCASE: a xor a = 0 (taint removed)
      if(type == PROP_XOR && opnd_is_reg(src2) && src1_reg == opnd_get_reg(src2))
      {
        LDUMP("InsDetail:\tRemoving taint from %s.\n", REGNAME(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                             OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVZX)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from %s to %s zero extend %d bytes to %d bytes.\n", REGNAME(src1_reg), 
        	             REGNAME(dst_reg), REGSIZE(src1_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2regzx, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVSX)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from %s to %s sign extend %d bytes to %d bytes.\n", REGNAME(src1_reg), 
        	             REGNAME(dst_reg), REGSIZE(src1_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2regsx, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOV)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint from %s to %s.\n", REGNAME(src1_reg), REGNAME(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      {
      	if (opnd_is_reg(src2))
      	{
      	  int src2_reg = opnd_get_reg(src2);

      	  if (src1_reg == src2_reg) // a = a + a
      	  {
            // SPECIALCASE: a + a = 2*a (taint stays the same)
      	    if (type == PROP_ADD || type == PROP_ADC || type == PROP_IMUL)
      	    {
      	      if (!opnd_same(src2, dst))
      	      {
                  dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, DBG_TAINT_NUM_PARAMS(2),
                               OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      	      }
      	      else
      	      {
      	      	// Nothing to do.
      	      }
      	    }
      	    // SPECIALCASE: a - a = 0 (taint removed)
      	    else if (type == PROP_SUB || type == PROP_SBB)
      	    {
              LDUMP("InsDetail:\tRemoving taint from %s.\n", REGNAME(dst_reg));

              dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg_rm, false, DBG_TAINT_NUM_PARAMS(1),
                                   OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      	    }
      	    else
      	    {
      	      FAIL();
      	    }
      	  }
      	  else
      	  {
            LDUMP("InsDetail:\tDoing '%s' to taint from %s and %s -> %s.\n", PROP_NAMES[type], REGNAME(src1_reg), REGNAME(src2_reg), REGNAME(dst_reg));

            dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_regNreg2reg, false, DBG_TAINT_NUM_PARAMS(4),
                                   OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(src2_reg), OPND_CREATE_INT32(dst_reg),
                                       OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
          }
        }
        else if (opnd_is_immed(src2))
        {
            dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2reg, false, DBG_TAINT_NUM_PARAMS(2),
                            OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
        }
        else
        {
           FAIL();
        }
      }
      else if (prop_is_restrictor(type))
      {
      	//FIXME: implement it.
      }
      else
      {
      	FAIL();
      }
    }
    else if (opnd_is_rel_addr(dst))
    {
      /*
          register to relative memory.
      */

      app_pc addr;

      instr_get_rel_addr_target(instr, &addr);

      if (type == PROP_MOV)
      {
      	if (!opnd_same(src2, dst)) {  FAIL(); }

        LDUMP("InsDetail:\tTaint %s to pc-relative %llx, %d bytes.\n", 
                                        REGNAME(src1_reg), addr, REGSIZE(src1_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2constmem, false, DBG_TAINT_NUM_PARAMS(2), 
                                 OPND_CREATE_INT32(src1_reg), OPND_CREATE_INT64(addr) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_restrictor(type))
      {
      	//FIXME: implement it.
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
  // src: rel addr.
  else if (opnd_is_rel_addr(src1))
  {
    app_pc addr;

    instr_get_rel_addr_target(instr, &addr);

    int extend_from = opnd_size_in_bytes(opnd_get_size(src1));

    if (opnd_is_reg(dst))
    {
      /*
          relative memory to register.
      */

      reg_id_t dst_reg = opnd_get_reg(dst);

      if (!opnd_is_reg(src2) || dst_reg != opnd_get_reg(src2)) FAIL();

      if (type == PROP_MOV)
      {
        LDUMP("InsDetail:\tTaint from pc-relative %llx to %s %d bytes.\n", addr, REGNAME(dst_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_constmem2reg, false, DBG_TAINT_NUM_PARAMS(2),
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_binary(type))
      {
      	LDUMP("InsDetail:\tDoing '%s' to taint from pc-relative %llx to %s %d bytes.\n", PROP_NAMES[type], 
                  addr, REGNAME(dst_reg), REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mix_constmem2reg, false, DBG_TAINT_NUM_PARAMS(3),
                                OPND_CREATE_INT64(addr), OPND_CREATE_INT32(dst_reg),
                                   OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVZX)
      {
      	LDUMP("InsDetail:\tTaint from pc-relative %llx to %s %d bytes zero extended to %d bytes.\n", 
      		      addr, REGNAME(dst_reg), extend_from, REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_constmem2regzx, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(dst_reg),
                                   OPND_CREATE_INT32(extend_from) DBG_END_DR_CLEANCALL);
      }
      else if (type == PROP_MOVSX)
      {
      	LDUMP("InsDetail:\tTaint from pc-relative %llx to %s %d bytes sign extended to %d bytes.\n", 
      		      addr, REGNAME(dst_reg), extend_from, REGSIZE(dst_reg));

        dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_constmem2regsx, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(dst_reg),
                                   OPND_CREATE_INT32(extend_from) DBG_END_DR_CLEANCALL);
      }
      else if (prop_is_restrictor(type))
      {
      	//FIXME: implement it.
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
  else
  {
  	FAIL();
  }
}

static void opcode_pop(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  if (instr_num_srcs(instr) != 2 || instr_num_dsts(instr) != 2)
  {
  	FAIL();
  }

  opnd_t src = instr_get_src(instr, 1);
  opnd_t dst = instr_get_dst(instr, 0);

  if (!opnd_is_base_disp(src))
  {
  	FAIL();
  }

  if (!opnd_is_reg(instr_get_src(instr, 0)) || opnd_get_reg(instr_get_src(instr, 0)) != DR_REG_RSP)
  {
  	FAIL();
  }

  if (!opnd_is_reg(instr_get_dst(instr, 1)) || opnd_get_reg(instr_get_dst(instr, 1)) != DR_REG_RSP)
  {
  	FAIL();
  }

  reg_id_t base_reg  = opnd_get_base(src);
  reg_id_t index_reg = opnd_get_index(src);
  reg_id_t seg_reg   = opnd_get_segment(src);
  int scale          = opnd_get_scale(src);
  int disp           = opnd_get_disp(src);

  if (opnd_is_reg(dst))
  {
    int dst_reg = opnd_get_reg(dst);

    LDUMP("InsDetail:\tTaint from base+disp %s:%s + %d*%s + %d to %s %d bytes.\n", 
                                       REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                            REGNAME(index_reg), disp, REGNAME(dst_reg), REGSIZE(dst_reg));

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_mem2reg, false, DBG_TAINT_NUM_PARAMS(6),
                             OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                 OPND_CREATE_INT32(scale),  OPND_CREATE_INT32(disp), OPND_CREATE_INT32(dst_reg) DBG_END_DR_CLEANCALL);
  }
  else
  {
  	FAIL();
  }

}

static void opcode_push(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  if (instr_num_srcs(instr) != 2 || instr_num_dsts(instr) != 2)
  {
  	FAIL();
  }

  opnd_t src = instr_get_src(instr, 0);
  opnd_t dst = instr_get_dst(instr, 1);

  if (!opnd_is_base_disp(dst))
  {
  	FAIL();
  }

  if (!opnd_is_reg(instr_get_src(instr, 1)) || opnd_get_reg(instr_get_src(instr, 1)) != DR_REG_RSP)
  {
  	FAIL();
  }

  if (!opnd_is_reg(instr_get_dst(instr, 0)) || opnd_get_reg(instr_get_dst(instr, 0)) != DR_REG_RSP)
  {
  	FAIL();
  }

  reg_id_t base_reg  = opnd_get_base(dst);
  reg_id_t index_reg = opnd_get_index(dst);
  reg_id_t seg_reg   = opnd_get_segment(dst);
  int scale          = opnd_get_scale(dst);
  int disp           = opnd_get_disp(dst);

  if (opnd_is_immed(src))
  {
    int access_size = -1*disp;

    LDUMP("AAQInsDetail:\tRemove taint at base+disp %s: %s + %d*%s + %d, %d bytes.\n",
                               REGNAME(seg_reg), REGNAME(base_reg), scale, REGNAME(index_reg), disp, access_size);

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_baseindexmem_rm, false, DBG_TAINT_NUM_PARAMS(6),
                          OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                 OPND_CREATE_INT32(scale), OPND_CREATE_INT32(disp), 
                                     OPND_CREATE_INT32(access_size) DBG_END_DR_CLEANCALL);
  }
  else if (opnd_is_reg(src))
  {
  	int src_reg = opnd_get_reg(src);

    LDUMP("InsDetail:\tTaint from %s to base+disp %s: %s + %d*%s + %d, %d bytes.\n", 
                                REGNAME(src_reg), REGNAME(seg_reg), REGNAME(base_reg), scale, 
                                     REGNAME(index_reg), disp, REGSIZE(src_reg));

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_mv_reg2mem, false, DBG_TAINT_NUM_PARAMS(6), 
                             OPND_CREATE_INT32(src_reg), OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), 
                                 OPND_CREATE_INT32(index_reg), OPND_CREATE_INT32(scale), 
                                     OPND_CREATE_INT32(disp) DBG_END_DR_CLEANCALL);
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

  int opcode = instr_get_opcode(instr);

  //LDEBUG("AAAAAAAAA src: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(src), 
  //                                      opnd_is_immed(src),  opnd_is_base_disp(src),  opnd_is_mem_instr(src), opnd_is_rel_addr(src));
  //LDEBUG("AAAAAAAAA dst: isreg: %d isimmed: %d isbaseindex: %d ismem: %d isreladdr %d\n", opnd_is_reg(dst), 
  //                                     opnd_is_immed(dst),  opnd_is_base_disp(dst),  opnd_is_mem_instr(dst), opnd_is_rel_addr(dst));


  if (opcode == OP_movsx || opcode == OP_movsxd)
  {
    propagate(drcontext, instr, ilist, src, dst, dst, PROP_MOVSX);
  }
  else if (opcode == OP_mov_ld || opcode == OP_mov_st || opcode == OP_mov_imm)
  {
    propagate(drcontext, instr, ilist, src, dst, dst, PROP_MOV);
  }
  else if (opcode == OP_movzx)
  {
    propagate(drcontext, instr, ilist, src, dst, dst, PROP_MOVZX);
  }
  else
  {
    FAIL();
  }
}

static void opcode_cmp(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t first  = instr_get_src(instr, 0);
  opnd_t second = instr_get_src(instr, 1);

  int type = -1;

  int opcode = instr_get_opcode(instr);

  if (opcode == OP_cmp)
  {
  	type = PROP_CMP;
  }
  else if (opcode == OP_test)
  {
  	type = PROP_TEST;
  }
  else
  {
  	FAIL();
  }

  if (opnd_is_reg(first))
  {
    int reg1 = opnd_get_reg(first);

  	if (opnd_is_reg(second))
  	{
      int reg2 = opnd_get_reg(second);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_reg2reg, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT32(reg1), OPND_CREATE_INT32(reg2), OPND_CREATE_INT32(type)
                                      DBG_END_DR_CLEANCALL);
  	}
  	else if (opnd_is_immed(second))
  	{
       dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_reg2imm, false, DBG_TAINT_NUM_PARAMS(1),
                                 OPND_CREATE_INT32(reg1), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
  	}
    else if (opnd_is_base_disp(second))
    {
      reg_id_t base_reg  = opnd_get_base(second);
      reg_id_t index_reg = opnd_get_index(second);
      reg_id_t seg_reg   = opnd_get_segment(second);
      int scale          = opnd_get_scale(second);
      int disp           = opnd_get_disp(second);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_reg2mem, false, DBG_TAINT_NUM_PARAMS(6),
                                 OPND_CREATE_INT32(reg1), OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), 
                                     OPND_CREATE_INT32(index_reg),  OPND_CREATE_INT32(scale),  
                                          OPND_CREATE_INT32(disp), OPND_CREATE_INT32(type)
                                              DBG_END_DR_CLEANCALL);
    }
  	else
  	{
  	  FAIL();
  	}
  }
  else if (opnd_is_base_disp(first))
  {
    reg_id_t base_reg  = opnd_get_base(first);
    reg_id_t index_reg = opnd_get_index(first);
    reg_id_t seg_reg   = opnd_get_segment(first);
    int scale          = opnd_get_scale(first);
    int disp           = opnd_get_disp(first);

    int size = opnd_size_in_bytes(opnd_get_size(first));

    if (opnd_is_reg(second))
  	{
      int reg2 = opnd_get_reg(second);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_mem2reg, false, DBG_TAINT_NUM_PARAMS(7),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale),  OPND_CREATE_INT32(disp), OPND_CREATE_INT32(size),
                                         OPND_CREATE_INT32(reg2), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
  	}
  	else if (opnd_is_immed(second))
  	{
       dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_mem2imm, false, DBG_TAINT_NUM_PARAMS(6),
                                 OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale), OPND_CREATE_INT32(disp), OPND_CREATE_INT32(size),
                                         OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
  	}
  	else
  	{
  	  FAIL();
  	}
  }
  else if (opnd_is_rel_addr(first))
  {
    app_pc addr;

    instr_get_rel_addr_target(instr, &addr);

    int size = opnd_size_in_bytes(opnd_get_size(first));

    if (opnd_is_reg(second))
  	{
      int reg2 = opnd_get_reg(second);

      dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_constmem2reg, false, DBG_TAINT_NUM_PARAMS(3),
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(size), OPND_CREATE_INT32(reg2), 
                                     OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
  	}
  	else if (opnd_is_immed(second))
  	{
       dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cmp_constmem2imm, false, DBG_TAINT_NUM_PARAMS(2),
                                 OPND_CREATE_INT64(addr), OPND_CREATE_INT32(size), OPND_CREATE_INT32(type) DBG_END_DR_CLEANCALL);
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

static void process_conditional_jmp(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  int opcode = instr_get_opcode(instr);

  if (opcode == OP_call || opcode == OP_ret)
  {
    // Do nothing.
  }
  else if (opcode == OP_jle_short || opcode == OP_jle || opcode == OP_jl_short || opcode == OP_jl)
  {
    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cond_jmp, false, DBG_TAINT_NUM_PARAMS(1),
                           OPND_CREATE_INT32(COND_LESS)  DBG_END_DR_CLEANCALL);
  }
  else if (opcode == OP_jnl_short || opcode == OP_jnl || opcode == OP_jnle_short || opcode == OP_jnle)
  {
    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cond_jmp, false, DBG_TAINT_NUM_PARAMS(1),
                            OPND_CREATE_INT32(COND_MORE) DBG_END_DR_CLEANCALL);
  }
  else if (opcode == OP_jnz || opcode == OP_jnz_short)
  {
    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cond_jmp, false, DBG_TAINT_NUM_PARAMS(1),
                            OPND_CREATE_INT32(COND_NONZERO) DBG_END_DR_CLEANCALL);
  }
  else if (opcode == OP_jz || opcode == OP_jz_short)
  {
    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_cond_jmp, false, DBG_TAINT_NUM_PARAMS(1),
                            OPND_CREATE_INT32(COND_ZERO) DBG_END_DR_CLEANCALL);
  }
  else
  {
  	if (started_ == MODE_ACTIVE)  // Ignore other cases for now, since we cannot debug.
  	{
  	  FAIL();
  	}
  }
}

// src2 == dst
static void opcode_add(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  opnd_t src1 = instr_get_src(instr, 0);
  opnd_t src2 = instr_get_src(instr, 1);
  opnd_t dst  = instr_get_dst(instr, 0);

  int opcode = instr_get_opcode(instr);

  // Needs a bit different treatment.
  if (opcode == OP_imul)
  {
    if (instr_num_srcs(instr) == 2 && instr_num_dsts(instr) == 2)
    {
      opnd_t dst2  = instr_get_dst(instr, 1);

      /*
      Since effectively it becomes an 'or' of src1 and src2, de don't care about order
      */

      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_IMUL);
      propagate(drcontext, instr, ilist, src1, src2, dst2, PROP_IMUL);
    }
    else if (instr_num_srcs(instr) == 2 && instr_num_dsts(instr) == 1)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_IMUL);
    }
    else
    {
      FAIL();
    }
  }
  else
  {
    if (!opnd_same(src2, dst)) FAIL();
    if (instr_num_srcs(instr) != 2 || instr_num_dsts(instr) != 1) FAIL();

    if (opcode == OP_sub)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_SUB);
    }
    else if (opcode == OP_add)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_ADD);
    }
    else if (opcode == OP_or)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_OR);
    }
    else if (opcode == OP_adc)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_ADC);
    }
    else if (opcode == OP_sbb)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_SBB);
    }
    else if (opcode == OP_and)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_AND);
    }
    else if (opcode == OP_xor)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_XOR);
    }
    else if (opcode == OP_imul)
    {
      propagate(drcontext, instr, ilist, src1, src2, dst, PROP_IMUL);
    }
    else
    {
    	FAIL();
    }
  }
}

static void opcode_ignore(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
}

static void wrong_opcode(void *drcontext, instr_t *instr, instrlist_t *ilist)
{ 
//  LERROR("ERROR! instruction not implemented.\n");

  LWARNING("Warning! unknown opcode.\n");
//  FAIL();
}

static void opcode_call(void *drcontext, instr_t *instr, instrlist_t *ilist)
{
  /*
  Process boundedness updates.
  */
  process_conditional_jmp(drcontext, instr, ilist);

  if (!instr_is_cti(instr)) FAIL();

  opnd_t t = instr_get_target(instr);

  // opnd_get_reg(t) == DR_REG_RSP for 'ret'.
  if (opnd_is_reg(t))
  {
    int reg = opnd_get_reg(t);

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_check_jmp_reg, false, DBG_TAINT_NUM_PARAMS(1),
                            OPND_CREATE_INT32(reg) DBG_END_DR_CLEANCALL);

    return;
  }
  else if (opnd_is_base_disp(t))
  {
    reg_id_t base_reg  = opnd_get_base(t);
    reg_id_t index_reg = opnd_get_index(t);
    reg_id_t seg_reg   = opnd_get_segment(t);
    int scale          = opnd_get_scale(t);
    int disp           = opnd_get_disp(t);

    dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_check_jmp_mem, false, DBG_TAINT_NUM_PARAMS(5),
                            OPND_CREATE_INT32(seg_reg), OPND_CREATE_INT32(base_reg), OPND_CREATE_INT32(index_reg),
                                     OPND_CREATE_INT32(scale),  OPND_CREATE_INT32(disp) DBG_END_DR_CLEANCALL);

    return;
  }

  app_pc pc;

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

  dr_insert_clean_call(drcontext, ilist, instr, (void *) nshr_taint_check_jmp_immed, false, DBG_TAINT_NUM_PARAMS(1),
                            OPND_CREATE_INT64(pc) DBG_END_DR_CLEANCALL);
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

  instrFunctions[OP_LABEL]          = opcode_ignore;	// 3
  instrFunctions[OP_add]			= opcode_add;		// 4
  instrFunctions[OP_or]				= opcode_add;		// 5
  instrFunctions[OP_adc]			= opcode_add;		// 6
  instrFunctions[OP_sbb]			= opcode_add;		// 7
  instrFunctions[OP_and]			= opcode_add;		// 8
  instrFunctions[OP_daa]			= wrong_opcode;		// 9 (BCD)
  instrFunctions[OP_sub]			= opcode_add;		// 10
  instrFunctions[OP_das]			= wrong_opcode;		// 11 (BCD)
  instrFunctions[OP_xor]			= opcode_add;		// 12
  instrFunctions[OP_aaa]			= wrong_opcode;		// 13 (BCD)
  instrFunctions[OP_cmp]			= opcode_cmp;		// 14
  instrFunctions[OP_aas]			= wrong_opcode;		// 15 (BCD)
  instrFunctions[OP_inc]			= opcode_ignore;	// 16
  instrFunctions[OP_dec]			= opcode_ignore;	// 17
  instrFunctions[OP_push]			= opcode_push;		// 18
  instrFunctions[OP_push_imm]		= opcode_push;		// 19
  instrFunctions[OP_pop]            = opcode_pop;		// 20
  instrFunctions[OP_pusha]          = wrong_opcode;		// 21
  instrFunctions[OP_popa]           = wrong_opcode;		// 22
  instrFunctions[OP_bound]          = wrong_opcode;		// 23
  instrFunctions[OP_arpl]           = wrong_opcode;		// 24
  instrFunctions[OP_imul]			= opcode_add;		// 25
  instrFunctions[OP_jo_short]		= opcode_call;		// 26
  instrFunctions[OP_jno_short]		= opcode_call;		// 27
  instrFunctions[OP_jb_short]		= opcode_call;		// 28
  instrFunctions[OP_jnb_short]		= opcode_call;		// 29
  instrFunctions[OP_jz_short]		= opcode_call;		// 30
  instrFunctions[OP_jnz_short]		= opcode_call;		// 31
  instrFunctions[OP_jbe_short]		= opcode_call;		// 32
  instrFunctions[OP_jnbe_short]		= opcode_call;		// 33
  instrFunctions[OP_js_short]		= opcode_call;		// 34
  instrFunctions[OP_jns_short]		= opcode_call;		// 35
  instrFunctions[OP_jp_short]		= opcode_call;		// 36
  instrFunctions[OP_jnp_short]		= opcode_call;		// 37
  instrFunctions[OP_jl_short]		= opcode_call;		// 38
  instrFunctions[OP_jnl_short]		= opcode_call;		// 39
  instrFunctions[OP_jle_short]		= opcode_call;		// 40
  instrFunctions[OP_jnle_short]		= opcode_call;		// 41
  instrFunctions[OP_call]			= opcode_call;		// 42
  instrFunctions[OP_call_ind]		= opcode_call;		// 43
  instrFunctions[OP_call_far]		= opcode_call;		// 44
  instrFunctions[OP_call_far_ind]	= opcode_call;		// 45
  instrFunctions[OP_jmp]			= opcode_call;		// 46
  instrFunctions[OP_jmp_short]		= opcode_call;		// 47
  instrFunctions[OP_jmp_ind]		= opcode_call;		// 48
  instrFunctions[OP_jmp_far]		= opcode_call;		// 49
  instrFunctions[OP_jmp_far_ind]	= opcode_call;		// 50

  instrFunctions[OP_mov_ld]			= opcode_mov;		// 55	Can be: mem2reg
  instrFunctions[OP_mov_st]			= opcode_mov;		// 56	Can be: imm2mem, reg2mem, reg2reg.
  instrFunctions[OP_mov_imm]		= opcode_mov;		// 57   Can be: imm2reg.
  instrFunctions[OP_mov_seg]	    = wrong_opcode;   	// 58
  instrFunctions[OP_mov_priv]		= wrong_opcode;		// 59
  instrFunctions[OP_test]			= opcode_cmp;		// 60 
  instrFunctions[OP_lea]			= opcode_lea;		// 61

  instrFunctions[OP_ret]			= opcode_call;		// 70

  instrFunctions[OP_syscall]		= opcode_ignore;	// 95 syscall processed by dr_register_post_syscall_event.


  instrFunctions[OP_jo]				= opcode_call; 		// 152
  instrFunctions[OP_jno]			= opcode_call; 		// 153
  instrFunctions[OP_jb]				= opcode_call; 		// 154
  instrFunctions[OP_jnb]			= opcode_call; 		// 155
  instrFunctions[OP_jz]				= opcode_call; 		// 156
  instrFunctions[OP_jnz]			= opcode_call; 		// 157
  instrFunctions[OP_jbe]			= opcode_call; 		// 158
  instrFunctions[OP_jnbe]			= opcode_call; 		// 159
  instrFunctions[OP_js]				= opcode_call; 		// 160
  instrFunctions[OP_jns]			= opcode_call; 		// 161
  instrFunctions[OP_jp]				= opcode_call; 		// 162
  instrFunctions[OP_jnp]			= opcode_call; 		// 163
  instrFunctions[OP_jl]				= opcode_call; 		// 164
  instrFunctions[OP_jnl]			= opcode_call; 		// 165
  instrFunctions[OP_jle]			= opcode_call; 		// 166
  instrFunctions[OP_jnle]			= opcode_call; 		// 167

  instrFunctions[OP_movzx]          = opcode_mov;		// 195

  instrFunctions[OP_movsx]          = opcode_mov;		// 200

  instrFunctions[OP_nop]            = opcode_ignore;	// 381

  instrFunctions[OP_movsxd]         = opcode_mov;		// 597
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
  	    (instrFunctions[opcode] == opcode_call && (started_ == MODE_IN_LIBC || started_ == MODE_BEFORE_MAIN)))
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


