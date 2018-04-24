#ifndef THESIS_MODULE_H
#define THESIS_MODULE_H

#include <stdint.h>

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

  // this ID can be of 
  int size;
  int index;

} ID_entity;

/*
We need this because we don't want to carry all the 
operations with all bytes if taint is e.g 4-byte
*/

typedef struct {
  int id;
  int size;
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

#define MEMTAINTISEMPTY(index, address)     (taint_[index][(address) % TAINTMAP_SIZE][1] == -1)
#define MEMTAINTADDR(index, address)        (taint_[index][(address) % TAINTMAP_SIZE][0])
#define MEMTAINTVAL(index, address)         (taint_[index][(address) % TAINTMAP_SIZE][1])
#define REGNAME(mask)                       (reg_mask_names[(mask & 0xFF0000) >> 16])
#define REGINDEX(mas)                       ((mask & 0xFF0000) >> 16);
#define REGSTART(mask)                      ((mask & 0xFF00) >> 8)
#define REGSIZE(mask)                       (mask & 0xFF)
#define REGTAINT(mask, offset)              (taintReg_[(mask & 0xFF0000) >> 16][((mask & 0xFF00) >> 8) + offset])
#define ADDR(address) ((address) % TAINTMAP_SIZE)

#define REGTAINTID(mask, offset)            (iids_[(taintReg_[(mask & 0xFF0000) >> 16][((mask & 0xFF00) >> 8) + offset])].id)
#define REGTAINTSIZE(mask, offset)          (iids_[(taintReg_[(mask & 0xFF0000) >> 16][((mask & 0xFF00) >> 8) + offset])].size)
#define MEMTAINTID(index, address)          (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].id)
#define MEMTAINTSIZE(index, address)        (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].size)
#define MEMTAINTINDEX(index, address)       (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].index)

#define LOGMEMTAINT(index, address)         (taint_[index][(address) % TAINTMAP_SIZE][1]), (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].id), (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].size), (iids_[(taint_[index][(address) % TAINTMAP_SIZE][1])].index)
#define IIDTOID(iid)                        (iids_[iid].id)
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


extern int64_t taint_[TAINTMAP_NUM][TAINTMAP_SIZE][2];
extern int64_t taintReg_[16][8];

extern instrFunc instrFunctions[MAX_OPCODE];

extern int nextUID;
extern int nextID;
extern int nextIID;

int nshr_tid_new_id();
int nshr_tid_new_id_get();
int nshr_tid_new_iid(int id, int size, int index);
int nshr_tid_new_iid_get();
int nshr_tid_new_uid(int fd);
int nshr_tid_copy_id(int id);
int nshr_tid_modify_id(int id, enum prop_type operation, int64 value, int is_id);

int nshr_reg_fix_size(int index_reg);

//
// Function declarations.
//


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

// e.g dst_reg+=val, dst_reg^=val.....
void nshr_taint_mix_val2reg(int dst_reg, int64 value, int type);

// dst_reg = src_reg+val
void nshr_taint_add_val2newreg(int src_reg, int dst_reg, int64 value);


void nshr_taint_ret();
void nshr_taint_jmp_reg(int dst_reg);

// instructions.
dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, 
	                              bool translating, void *user_data);
void nshr_init_opcodes(void);

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data);
void nshr_post_scanf(void *wrapcxt, void *user_data);


#endif
