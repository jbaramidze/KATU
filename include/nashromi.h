#ifndef THESIS_MODULE_H
#define THESIS_MODULE_H

#include <stdint.h>

// Do additional checks, while testing
#define CHECKS

//
// Constants.
//

#define MAX_FD                255
#define MAX_UID               1000
#define MAX_ID                1000000
#define MAX_IID               4000000
#define MAX_OPCODE            2048
#define DEFAULT_OPERATIONS    8
#define TAINTMAP_NUM          10
#define TAINTMAP_SIZE         65536

enum prop_type {
  PROP_MOV,
  PROP_MOVZX,
  PROP_ADD,
  PROP_SUB,
  PROP_AND,
  PROP_OR,
  PROP_XOR,
  PROP_MULT,
  PROP_ADC,
  PROP_SBB

};

int is_binary(enum prop_type type );


enum mode {
  MODE_IGNORING,
  MODE_ACTIVE,
  MODE_IN_LIBC,

};

//
// Types.
//

typedef struct {
  bool used;
  char *path;

} Fd_entity;

typedef struct {
  int fd;

} UID_entity;

typedef struct {
  enum prop_type type;
  int64 value;
  int is_id;

} Operations;


typedef struct {
  int uid;
  Operations ops[DEFAULT_OPERATIONS];
  int ops_size;

  // no absolutely necessary.
  int size;
} ID_entity;

/*
We need this because we don't want to carry all the 
operations with all bytes if taint is e.g 4-byte
*/

typedef struct {
  int id;
  int index;

} IID_entity;

typedef void (*instrFunc)(void *, instr_t *, instrlist_t *);



//
// Utility definitions.
//

#define STOP_IF_NOT_ACTIVE(retval)    if (started_ != MODE_ACTIVE)  {  return retval;  }
#define STOP_IF_IGNORING(retval)    if (started_ == MODE_IGNORING)  {  return retval;  }
#define UNUSED(expr) 			do { (void)(expr); } while (0)

#define FAIL() { dr_printf("FAIL! at %s:%d.\n", __FILE__, __LINE__); \
                 				exit(-1); }

// Encode in 3 bytes: index of register, which byte to start from in reg. and how many bytes to taint.
#define ENCODE_REG(reg)			reg_mask_index[reg] * 0x10000 + \
					reg_mask_start[reg] * 0x100   + \
					opnd_size_in_bytes(reg_get_size(reg))

#define DECODE_REG1(mask)		int reg_index1 =  (mask & 0xFF0000) >> 16;  	\
					int reg_start1 =  (mask & 0xFF00) >> 8;		\
					int reg_size1  =  mask & 0xFF

#define DECODE_REG2(mask)		int reg_index2 =  (mask & 0xFF0000) >> 16; 	\
					int reg_start2 = (mask & 0xFF00) >> 8;

#define DECODE_REG3(mask)		int reg_index3 =  (mask & 0xFF0000) >> 16; 	\
					int reg_start3 = (mask & 0xFF00) >> 8;

#define GET_CONTEXT()			dr_mcontext_t mcontext = {sizeof(mcontext),DR_MC_ALL}; \
					void *drcontext = dr_get_current_drcontext(); \
					dr_get_mcontext(drcontext, &mcontext)

static const char *PROP_NAMES[] = {
    "mov", "movzx", "add", "sub", "and", "or", "xor", "mul", "adc", "sbb"
};

static const char *reg_mask_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", 
                                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

// return 0 on 1, 1 on 2, 2 on 4 and 3 on 8
static const int sizes_to_indexes[] = {-1, 0, 1, -1, 2, -1, -1, -1, 3 };
#define SIZE_TO_INDEX(mask)                  (sizes_to_indexes[mask & 0xFF])  


#define REGNAME(mask)                       (reg_mask_names[(mask & 0xFF0000) >> 16])
#define REGINDEX(mask)                      ((mask & 0xFF0000) >> 16)
#define REGSTART(mask)                      ((mask & 0xFF00) >> 8)
#define REGSIZE(mask)                       (mask & 0xFF)
          

#define ADDR(address) ((address) % TAINTMAP_SIZE)

#define MEMTAINTISEMPTY(index, address)              mem_taint_is_empty(index, address)
#define MEMTAINTADDR(index, address)                 mem_taint_get_addr(index, address)
#define SETMEMTAINTADDR(index, address, value)       mem_taint_set_addr(index, address, value)
#define MEMTAINTVAL1(index, address)                 mem_taint_get_value(index, address, 0)
#define MEMTAINTVAL2(index, address)                 mem_taint_get_value(index, address, 1)
#define MEMTAINTVAL4(index, address)                 mem_taint_get_value(index, address, 2)
#define MEMTAINTVAL8(index, address)                 mem_taint_get_value(index, address, 3)
#define MEMTAINTVAL(index, address, size)            mem_taint_get_value(index, address, size)
#define SETMEMTAINTVAL1(index, address, value)       mem_taint_set_value(index, address, 0, value)
#define SETMEMTAINTVAL2(index, address, value)       mem_taint_set_value(index, address, 1, value)
#define SETMEMTAINTVAL4(index, address, value)       mem_taint_set_value(index, address, 2, value)
#define SETMEMTAINTVAL8(index, address, value)       mem_taint_set_value(index, address, 3, value)
#define SETMEMTAINTVAL(index, address, size, value)  mem_taint_set_value(index, address, size, value)

#define REGTAINTVAL1(mask, offset)                   reg_taint_get_value(mask, offset, 0) 
#define REGTAINTVAL2(mask, offset)                   reg_taint_get_value(mask, offset, 1) 
#define REGTAINTVAL4(mask, offset)                   reg_taint_get_value(mask, offset, 2) 
#define REGTAINTVAL8(mask, offset)                   reg_taint_get_value(mask, offset, 3)
#define REGTAINTVAL(mask, offset, size)              reg_taint_get_value(mask, offset, size)
#define SETREGTAINTVAL(mask, offset, size, value)    reg_taint_set_value(mask, offset, size, value)


#define REGTAINTVALS_LOG(reg, offset)      reg_taint_get_value(reg, i, 0), reg_taint_get_value(reg, i, 1), reg_taint_get_value(reg, i, 2), reg_taint_get_value(reg, i, 3)
#define MEMTAINTVALS_LOG(index, address)    mem_taint_get_value(index, addr, 0), mem_taint_get_value(index, addr, 1), mem_taint_get_value(index, addr, 2), mem_taint_get_value(index, addr, 3)

#define REGTAINT2MEMTAINT(mask, offset, index, address) mem_taint_set_value(index, address, 0, reg_taint_get_value(mask, offset, 0)); \
                                                        mem_taint_set_value(index, address, 1, reg_taint_get_value(mask, offset, 1)); \
                                                        mem_taint_set_value(index, address, 2, reg_taint_get_value(mask, offset, 2)); \
                                                        mem_taint_set_value(index, address, 3, reg_taint_get_value(mask, offset, 3));

#define MEMTAINT2REGTAINT(mask, offset, index, address) reg_taint_set_value(mask, offset, 0, mem_taint_get_value(index, address, 0)); \
                                                        reg_taint_set_value(mask, offset, 1, mem_taint_get_value(index, address, 1)); \
                                                        reg_taint_set_value(mask, offset, 2, mem_taint_get_value(index, address, 2)); \
                                                        reg_taint_set_value(mask, offset, 3, mem_taint_get_value(index, address, 3));

#define REGTAINT2REGTAINT(mask1, offset1, mask2, offset2) reg_taint_set_value(mask1, offset1, 0, reg_taint_get_value(mask2, offset2, 0)); \
                                                          reg_taint_set_value(mask1, offset1, 1, reg_taint_get_value(mask2, offset2, 1)); \
                                                          reg_taint_set_value(mask1, offset1, 2, reg_taint_get_value(mask2, offset2, 2)); \
                                                          reg_taint_set_value(mask1, offset1, 3, reg_taint_get_value(mask2, offset2, 3));


#define REGTAINTRM(mask, offset) reg_taint_set_value(mask, offset, 0, -1); \
                                 reg_taint_set_value(mask, offset, 1, -1); \
                                 reg_taint_set_value(mask, offset, 2, -1); \
                                 reg_taint_set_value(mask, offset, 3, -1);

#define MEMTAINTRM(index, address) mem_taint_set_value(index, address, 0, -1); \
                                   mem_taint_set_value(index, address, 1, -1); \
                                   mem_taint_set_value(index, address, 2, -1); \
                                   mem_taint_set_value(index, address, 3, -1);



#define MEMTAINTED(index, address)          (mem_taint_get_value(index, address, 0) > 0 || \
                                             mem_taint_get_value(index, address, 1) > 0 || \
                                             mem_taint_get_value(index, address, 2) > 0 || \
                                             mem_taint_get_value(index, address, 3) > 0)

#define REGTAINTED(mask, offset)            (reg_taint_get_value(mask, offset, 0) > 0 || \
                                             reg_taint_get_value(mask, offset, 1) > 0 || \
                                             reg_taint_get_value(mask, offset, 2) > 0 || \
                                             reg_taint_get_value(mask, offset, 3) > 0)



#define REGTAINTID(mask, offset)            (iids_[(taintReg_[(mask & 0xFF0000) >> 16][((mask & 0xFF00) >> 8) + offset])].id)
#define MEMTAINTID(index, address)          (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].id)
#define MEMTAINTINDEX(index, address)       (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].index)


#define IID2INDEX(iid)                      (iids_[iid].index)
#define IID2ID(iid)                         (iids_[iid].id)
#define ID2UID(id)                          (ids_[id].uid)
#define ID2SIZE(id)                         (ids_[id].size)
#define ID2OPSIZE(id)                       (ids_[id].ops_size)
#define ID2OP(id, index)                    (ids_[id].ops[index])
//
// Logging definitions.
//

#ifdef LOGTEST
#define LTEST(...) dr_printf(__VA_ARGS__)
#else
#define LTEST(...) 
#endif

#ifdef LOGDEBUG
#define LDEBUG(...) dr_printf(__VA_ARGS__)
#else
#define LDEBUG(...) 
#endif

#ifdef LOGDUMP
#define LDUMP(...) dr_printf(__VA_ARGS__)
#else
#define LDUMP(...)
#endif

#define LERROR(...) dr_printf(__VA_ARGS__)

/*
Specific logging functions.
*/

#if defined LOGDEBUG
#define LDEBUG_TAINT(A, ...) dr_printf(__VA_ARGS__)
#elif defined LOGTEST
#define LDEBUG_TAINT(A, ...) if (A) dr_printf(__VA_ARGS__)
#else
#define LDEBUG_TAINT(A, ...)
#endif

#if defined LOGDUMP
#define LDUMP_TAINT(i, A, ...) dr_printf(__VA_ARGS__)
#elif defined LOGTEST
#define LDUMP_TAINT(i, A, ...) if ((A) && i == 0) dr_printf(__VA_ARGS__)				
#else
#define LDUMP_TAINT(i, A, ...)
#endif

//
// Global variables.
//


extern enum mode started_;

extern Fd_entity  fds_[MAX_FD];
extern UID_entity uids_[MAX_UID];
extern ID_entity  ids_[MAX_ID];
extern IID_entity iids_[MAX_IID];

extern instrFunc instrFunctions[MAX_OPCODE];

/****************************************************
        T A I N T   M E M   S T R U C T U R E
*****************************************************/
typedef struct _TaintMemStruct
{
  // This one is just used for hash matching.
  int64_t address[TAINTMAP_NUM][TAINTMAP_SIZE];

  // This one marks taint markings.
  int64_t value[TAINTMAP_NUM][TAINTMAP_SIZE][4];

} TaintMemStruct;

extern TaintMemStruct taint_mem_;

int mem_taint_is_empty(int index, uint64_t addr);
int mem_taint_find_index(uint64_t addr, int i);
int64_t mem_taint_get_addr(int index, uint64_t addr);
void    mem_taint_set_addr(int index, uint64_t addr, uint64_t value);
int64_t mem_taint_get_value(int index, uint64_t addr, int size);
void    mem_taint_set_value(int index, uint64_t addr, int size, uint64_t value);


/****************************************************
        T A I N T   R E G   S T R U C T U R E
*****************************************************/

typedef struct _TaintRegStruct
{
  // [which_reg][which_byte]
  int64_t value[16][8][4];

}  TaintRegStruct;

extern TaintRegStruct taint_reg_;

int64_t reg_taint_get_value(int reg, int offset, int size);
void    reg_taint_set_value(int reg, int offset, int size, uint64_t value);


/****************************************************
     U I D / U U I D / I D   H A N D L I N G
*****************************************************/

extern int nextUID;
extern int nextID;
extern int nextIID;

int nshr_tid_new_id();
int nshr_tid_new_id_get();
int nshr_tid_new_iid(int id, int index);
int nshr_tid_new_iid_get();
int nshr_tid_new_uid(int fd);
int nshr_tid_copy_id(int id);
int nshr_tid_modify_id(int id, enum prop_type operation, int64 value, int is_id);

int nshr_reg_taint_any(int reg);
int nshr_reg_get_or_fix_sized_taint(int index_reg);

//
// Function declarations.
//

void dump();

// syscalls.
void nshr_event_post_syscall(void *drcontext, int id);
bool nshr_event_pre_syscall(void *drcontext, int id);
bool nshr_syscall_filter(void *drcontext, int sysnum);

// taint.
void nshr_taint(reg_t addr, unsigned int size, int fd);

void nshr_taint_mv_2coeffregs2reg(int reg_mask1, int scale, int reg_mask2, int disp, int reg_mask3);
void nshr_taint_mv_reg2reg(int reg_mask1, int reg_mask2);
void nshr_taint_mv_mem2reg(int segment, int disp, int scale, int base, int index, int reg_mask); 
void nshr_taint_mv_mem2regzx(int segment, int disp, int scale, int base, int index, int reg_mask, int srcsize); 
void nshr_taint_mv_reg2mem(int segment, int reg_mask, int scale, int base, int index, int disp);
void nshr_taint_mv_constmem2reg(uint64 addr, int reg_mask); 
void nshr_taint_mv_reg2constmem(int reg_mask, uint64 addr); 
void nshr_taint_mv_reg_rm(int reg);
void nshr_taint_mv_baseindexmem_rm(int segment, int disp, int scale, int base, int index, int size);
void nshr_taint_mv_mem_rm(uint64 addr, int size);

// e.g dst_reg=src_reg+val, dst_reg=src_reg^val.....
void nshr_taint_mix_val2reg(int dst_reg, int src_reg, int64 value, int type);
// e.g dst_reg=src_reg+dst_reg, dst_reg=src_reg^dst_reg.....
void nshr_taint_mix_reg2reg(int dst_reg, int src_reg, int type);

// dst_reg = src_reg+val
void nshr_taint_add_val2reg(int src_reg, int dst_reg, int64 value);


void nshr_taint_ret();
void nshr_taint_jmp_reg(int dst_reg);

// instructions.
dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, 
	                              bool translating, void *user_data);
void nshr_init_opcodes(void);

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data);
void nshr_post_scanf(void *wrapcxt, void *user_data);


#endif
