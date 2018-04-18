#ifndef THESIS_MODULE_H
#define THESIS_MODULE_H

#include <stdint.h>

#define ENABLE_ASSERT

//
// Constants.
//

#define MAX_FD                255
#define MAX_UID               1000
#define MAX_ID                1000000
#define MAX_OPCODE            2048
#define DEFAULT_OPERATIONS    8
#define TAINTMAP_NUM          10
#define TAINTMAP_SIZE         65536

enum prop_type {
  PROP_MOV,
  PROP_ADD,
  PROP_SUB,
  PROP_AND,
  PROP_OR,
  PROP_XOR,
  PROP_MULT,
  PROP_ADC,
  PROP_SBB

};

//
// Types.
//

typedef int taint_t;

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

typedef void (*instrFunc)(void *, instr_t *, instrlist_t *);

//
// Utility definitions.
//

#define STOP_IF_NOT_STARTED(retval)  	if (started_ == 0)  {  return retval;  }
#define UNUSED(expr) 			do { (void)(expr); } while (0)

//
// Assert.
//

#ifdef ENABLE_ASSERT
#define ASSERT assert
#else
#define ASSERT
#endif

#define FAIL() dr_printf("FAIL! at %s:%d.\n", __FILE__, __LINE__); \
                 				exit(-1);

void assert(bool a);

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
    "mov", "add", "sub", "and", "or", "xor", "mul", "adc", "sbb"
};

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


extern bool started_;
extern Fd_entity fds_[MAX_FD];
extern UID_entity uids_[MAX_UID];
extern int64_t taint_[TAINTMAP_NUM][TAINTMAP_SIZE][2];
extern taint_t taintReg_[16][8];
extern instrFunc instrFunctions[MAX_OPCODE];
extern ID_entity ids_[MAX_ID];
extern int nextUID;
extern int nextID;

int newUID(int fd);
int changeID(int id, enum prop_type operation, int64 value, int is_id);

//
// Function declarations.
//


// syscalls.
void nshr_event_post_syscall(void *drcontext, int id);
bool nshr_event_pre_syscall(void *drcontext, int id);
bool nshr_syscall_filter(void *drcontext, int sysnum);

// taint.
void nshr_taint(reg_t addr, unsigned int size, int fd);

void nshr_taint_mv_2coeffregs2reg(int reg_mask1, int scale, int reg_mask2, int reg_mask3);
void nshr_taint_mv_reg2reg(int reg_mask1, int reg_mask2);
void nshr_taint_mv_mem2reg(int segment, int disp, int scale, int base, int index, int reg_mask); 
void nshr_taint_mv_reg2mem(int segment, int reg_mask, int scale, int base, int index, int disp);
void nshr_taint_mv_constmem2reg(uint64 addr, int reg_mask); 
void nshr_taint_mv_reg2constmem(int reg_mask, uint64 addr); 
void nshr_taint_mv_reg_rm(int reg);
void nshr_taint_mv_baseindexmem_rm(int segment, int disp, int scale, int base, int index, int size);
void nshr_taint_mv_mem_rm(uint64 addr, int size);

void nshr_taint_mix_reg_add(int dst_reg, int64 value, int type);

// instructions.
dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, 
	                              bool translating, void *user_data);
void nshr_init_opcodes(void);



#endif
