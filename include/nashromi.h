#ifndef THESIS_MODULE_H
#define THESIS_MODULE_H

#include <stdint.h>
#include "drsyms.h"
#include "lp_lib.h"
#include "hashtable.h"
#include "drvector.h"

// Do additional checks, while testing
#undef CHECKS

// Pass instruction among other params when tainting, to debug.
#undef DBG_PASS_INSTR

// Parse jump addresses
#undef DBG_PARSE_JUMPS

// Dump statistics
#undef PROCESS_STATISTICS

// Log paths.
#define NSHR_LOGFILE_PATH "/home/zhani/Thesis/project/build/nshr.log"
#define NSHR_DUMPFILE_PATH "/home/zhani/Thesis/project/build/nshr.dump"

#ifdef DBG_PASS_INSTR

  #define DBG_TAINT_NUM_PARAMS(x) (x+1)
  #define DGB_END_CALL_ARG , dbg_instr
  #define DGB_END_CALL_ARG_ALONE dbg_instr
  #define DBG_END_DR_CLEANCALL , OPND_CREATE_INT64(instr_dupl(instr))
  #define DBG_END_TAINTING_FUNC , instr_t *dbg_instr
  #define DBG_END_TAINTING_FUNC_ALONE instr_t *dbg_instr
  
  
  
  /*
  Specific logging functions.
  */
  
  #if defined LOGDEBUG
  #define LDEBUG_TAINT(A, ...) { log_instr(dbg_instr); dr_fprintf(logfile, __VA_ARGS__); }
  #elif defined LOGNORMAL
  #define LDEBUG_TAINT(A, ...) if (A) { log_instr(dbg_instr); dr_fprintf(logfile, __VA_ARGS__); }
  #else
  #define LDEBUG_TAINT(A, ...)
  #endif
  
  #if defined LOGDUMP
  #define LDUMP_TAINT(i, A, ...) { log_instr(dbg_instr); dr_fprintf(logfile, __VA_ARGS__); }
  #elif defined LOGNORMAL
  #define LDUMP_TAINT(i, A, ...) if ((A) && i == 0) { log_instr(dbg_instr); dr_fprintf(logfile, __VA_ARGS__); }
  #else
  #define LDUMP_TAINT(i, A, ...)
  #endif


#else

  #define DBG_TAINT_NUM_PARAMS(x) (x)
  #define DGB_END_CALL_ARG 
  #define DGB_END_CALL_ARG_ALONE
  #define DBG_END_DR_CLEANCALL
  #define DBG_END_TAINTING_FUNC
  #define DBG_END_TAINTING_FUNC_ALONE
  
  /*
  Specific logging functions.
  */
  
  #if defined LOGDEBUG
  #define LDEBUG_TAINT(A, ...) dr_fprintf(logfile, __VA_ARGS__)
  #elif defined LOGNORMAL
  #define LDEBUG_TAINT(A, ...) if (A) dr_fprintf(logfile, __VA_ARGS__)
  #else
  #define LDEBUG_TAINT(A, ...)
  #endif
  
  #if defined LOGDUMP
  #define LDUMP_TAINT(i, A, ...) dr_fprintf(logfile, __VA_ARGS__)
  #elif defined LOGNORMAL
  #define LDUMP_TAINT(i, A, ...) if ((A) && i == 0) dr_fprintf(logfile, __VA_ARGS__)        
  #else
  #define LDUMP_TAINT(i, A, ...)
  #endif

#endif

#define TAINT_BOUND_LOW  1
#define TAINT_BOUND_HIGH 2
#define TAINT_BOUND_FIX  4

//
// Constants.
//

#define MAX_FD                255
#define MAX_UID               10000000
#define MAX_ID                10000000
#define MAX_OPCODE            2048
#define MAX_FILE_HISTORY      4096
#define INITIAL_OPERATIONS    4
#define TAINTMAP_NUM          50
#define TAINTMAP_SIZE         65536
#define ILP_MAX_CONSTR        1000
#define HASH_BITS             13
#define INSTR_DUPL_SIZE       1048576

//
// Things to tweak.
//


// How big shifts shall we ignore and on how big shall we detaint?
#define DETAINT_SHIFT 0.8
#define IGNORE_SHIFT  0.1

// How many bytes in index shall be unbounded to consider it a vulnerability? 
// (e.g. if 1, we consider indexing by unbounded char vulnerability, whereas it is 
// observed in many correct situations.)
#define MIN_VULNERABILITIES 2


#define FD_MANUAL_TAINT 900
#define FD_CMD_ARG      901

extern const char *manual_taint_path;
extern const char *cmd_arg_taint_path;

extern instr_t *instr_pointers[INSTR_DUPL_SIZE];
extern int instr_next_pointer;

extern file_t logfile, dumpfile;
extern FILE * logfile_stream;

extern app_pc main_address;
extern app_pc tmp_addr;

enum prop_type {
  // MOV's
  PROP_MOV,
  PROP_MOVZX,
  PROP_MOVSX,
  // Binaries
  PROP_ADD,
  PROP_SUB,
  PROP_ADC,
  PROP_SBB,
  PROP_DIV,
  PROP_IMUL,
  // Restrictors
  PROP_OR,
  PROP_XOR,
  PROP_AND,
  // Others
  PROP_CMP,
  PROP_TEST,
  // Conditions
  COND_LESS,
  COND_MORE,
  COND_EQ,
  COND_NEQ,
  COND_NONZERO,
  COND_ZERO,
  COND_LESS_UNSIGNED,
  COND_MORE_UNSIGNED,
  COND_SIGN_BIT,
  COND_NOT_SIGN_BIT,

  // Extra
  PROP_NEG

};

enum shift_type {
  LOGICAL_LEFT,
  LOGICAL_RIGHT,
  ARITH_LEFT,
  ARITH_RIGHT,
  ROTATE_LEFT,
  ROTATE_RIGHT

};

static const char *SHIFT_NAMES[] = {
  "logical left", "logical right", "arithmetic left", "arithmetic right",
  "rotate left", "rotate right"

};

int get_shift_type(int opcode);


static const char *PROP_NAMES[] = {
    "mov", "movzx", "movsx", 
    "add", "sub", "add with carry", "sub with borrow", "div", "imul", 
    "or", "xor", "and",
    "cmp", "test",
    "if_less", "if_more", "if_equal", "if_notequal", "if_nonzero", "if_zero", 
    "if_less_unsigned", "if_more_unsigned", "if_sign_bit", "if_not_sign_bit",

    "negate"
};

int prop_is_binary(enum prop_type type );
int prop_is_mov(enum prop_type type );
int prop_is_restrictor(enum prop_type type );
int prop_is_cond_mov(enum prop_type type );


enum mode {
  MODE_IGNORING,
  MODE_ACTIVE,
  MODE_IN_LIBC,
  MODE_BEFORE_MAIN,
  MODE_IN_IGNORELIB

};

//
// Types.
//

typedef struct {
  int secure;
  const char *path;

} Fd_entity;

struct Group_restriction{
  int id;

  // Cannot have several types together! fix code in LP section to enable.
  int bound_type;
  struct Group_restriction *next;
};

typedef struct Group_restriction Group_restriction;

typedef struct {
  union {
    int fd;
    int file;

  } descriptor;

  int descr_type;

  // TAINT_BOUND_*
  int bounded;

  Group_restriction *gr;

} UID_entity;

typedef struct {
  enum prop_type type;
  int64 value;

} Operations;


typedef struct {
  int uid;
  drvector_t *ops_vector;

  int negated;

  // not used for now, just propagated.
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


typedef struct {
  int type;

  int taint1[8];
  int taint2[8];

  int valid;

} Eflags;

typedef void (*handleFunc)(DBG_END_TAINTING_FUNC_ALONE);


//
// Utility definitions.
//

#ifndef MIN
# define MIN(x, y) ((x) <= (y) ? (x) : (y))
#endif

#define STOP_IF_NOT_ACTIVE(retval)  if (started_ != MODE_ACTIVE)  {  return retval;  }
#define STOP_IF_IGNORING(retval)    if (started_ == MODE_IGNORING)  {  return retval;  }
#define UNUSED(expr)                do { (void)(expr); } while (0)

#define FAIL() { dr_printf("FAIL! at %s:%d.\n", __FILE__, __LINE__); \
                 dump(); \
                 exit(-1); }

#ifdef CHECKS

  #define FAILIF(statement) { if (statement) { dr_printf("FAIL! at %s:%d.\n", __FILE__, __LINE__); \
                                               dump(); \
                                               exit(-1); } }

#else

  #define FAILIF(statement) 

#endif

#define DIE(text) { dr_printf(text); dr_flush_file(logfile); dr_flush_file(dumpfile); exit(-1); }

#define GET_CONTEXT()      dr_mcontext_t mcontext = {sizeof(mcontext),DR_MC_ALL}; \
                           void *drcontext = dr_get_current_drcontext(); \
                           dr_get_mcontext(drcontext, &mcontext)


//  AX AX
// [AL AH EAX EAX RAX RAX RAX RAX]
//   8  7  6   5   4   3   2   1

// [base + index*scale + disp]

// for each register, specify where to start tainting from, according our table
static const int reg_mask_start[69] = { 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x0, 0x0, 0x0, 0x0 };

static const int reg_mask_index[69] =  {0,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
                                 0,   1,   2,   3,   0,   1,   2,   3,   8,   9,   10,  11,  12,  13,  14,  15,
                                 4,   5,   6,   7   };


// return 0 on 1, 1 on 2, 2 on 4 and 3 on 8
static const int sizes_to_indexes[] = {-1, 0, 1, -1, 2, -1, -1, -1, 3 };
#define SIZE_TO_INDEX(size)                  (sizes_to_indexes[size])  

#define REGNAME(reg)                       (get_register_name(reg))
#define REGINDEX(reg)                      (reg_mask_index[reg])
#define REGSTART(reg)                      (reg_mask_start[reg])
#define REGSIZE(reg)                       (opnd_size_in_bytes(reg_get_size(reg)))
          

#define ADDR(address) ((address) % TAINTMAP_SIZE)

#define MEMTAINTISEMPTY(index, address)              mem_taint_is_empty(index,  address)
#define MEMTAINTADDR(index, address)                 mem_taint_get_addr(index,  address)
#define SETMEMTAINTADDR(index, address, value)       mem_taint_set_addr(index,  address, value)
#define MEMTAINTVAL(index, address)                  mem_taint_get_value(index, address)
#define SETMEMTAINTVAL(index, address, value)        mem_taint_set_value(index, address, value)

#define REGVAL_BYTE(reg, offset)                     reg_get_byte_value(reg, offset)
#define REGVAL(reg)                                  reg_get_full_value(reg)
#define MEMVAL(address)                              (*(uint64_t *) address)
#define MEMVAL_BYTE(address)                         (*(unsigned char *) address)

#define REGTAINTVAL(reg, offset)                     reg_taint_get_value(reg, offset)
#define SETREGTAINTVAL(reg, offset, value)           reg_taint_set_value(reg, offset, value)

#define MEMTAINT2MEMTAINT(index1, address1, index2, address2) mem_taint_set_value(index2, address2, mem_taint_get_value(index1, address1))
#define REGTAINT2MEMTAINT(mask, offset, index, address)       mem_taint_set_value(index, address,   reg_taint_get_value(mask, offset))
#define MEMTAINT2REGTAINT(index, address, mask, offset)       reg_taint_set_value(mask,  offset,    mem_taint_get_value(index, address))
#define REGTAINT2REGTAINT(mask1, offset1, mask2, offset2)     reg_taint_set_value(mask2, offset2,   reg_taint_get_value(mask1, offset1))

#define REGTAINTRMALL(reg)                   reg_taint_rm_all(reg)
#define MEMTAINTRMALL(addr, size)            mem_taint_rm_all(addr, size);
#define REGTAINTRM(reg, offset)              reg_taint_set_value(reg,  offset, -1)
#define MEMTAINTRM(index, address)           mem_taint_set_value(index, address, -1)

#define MEMTAINTED(index, address)          (mem_taint_get_value(index, address) > 0)
#define REGTAINTED(reg, offset)             (reg_taint_get_value(reg, offset) > 0)

#define REGTAINTEDANY(reg)                  reg_taint_any(reg)
#define MEMTAINTEDANY(mem, size)            mem_taint_any(mem, size)

#define REGTAINTID(mask, offset)            (taintReg_[(mask & 0xFF0000) >> 16][((mask & 0xFF00) >> 8) + offset])
#define MEMTAINTID(index, address)          (taint_[index][(address) % TAINTMAP_SIZE][1])

#define ID2UID(id)                          (tid_[id].uid)
#define ID2SIZE(id)                         (tid_[id].size)
#define ID2OPSIZE(id)                       ((tid_[id].ops_vector == NULL) ? 0 : tid_[id].ops_vector -> entries)
#define ID2OPTYPE(id, index)                (((Operations *) tid_[id].ops_vector -> array[index]) -> type)
#define ID2OPVAL(id, index)                 (((Operations *) tid_[id].ops_vector -> array[index]) -> value)
#define ID2OPS(id)                          (tid_[id].ops_vector)

//
// Logging definitions.
//

#ifdef LOGWARNING
#define LWARNING(...) dr_fprintf(logfile, __VA_ARGS__)
#else
#define LWARNING(...) 
#endif


#ifdef LOGNORMAL
#define LTEST(...) dr_fprintf(logfile, __VA_ARGS__)
#else
#define LTEST(...) 
#endif

#ifdef LOGDEBUG
#define LDEBUG(...) dr_fprintf(logfile, __VA_ARGS__)
#else
#define LDEBUG(...) 
#endif

#ifdef LOGDUMP
  #ifdef LOG_LINES
  #define LDUMP(...) { dr_fprintf(logfile, "AT %d:  ", __LINE__); dr_fprintf(logfile, __VA_ARGS__); }
  #else
  #define LDUMP(...) dr_fprintf(logfile, __VA_ARGS__)
  #endif
#else
#define LDUMP(...)
#endif

#define LERROR(...) dr_printf(__VA_ARGS__)


//
// Global variables.
//


extern enum mode started_;

extern Eflags eflags_;


extern Fd_entity files_history_[MAX_FILE_HISTORY];
extern Fd_entity fds_history_[MAX_FILE_HISTORY];
extern uint64_t files_history_index_;
extern uint64_t fds_history_index_;


extern int   fds_[MAX_FD];
extern hashtable_t FILEs_;

extern UID_entity *uid_;
extern ID_entity  *tid_;

extern instrFunc instrFunctions[MAX_OPCODE];

extern lprec *lp;

extern hashtable_t func_hashtable;

extern app_pc return_to;

extern app_pc ignore_vector[64];
extern int ignore_vector_size;


extern hashtable_t jump_addr_hashtable;
extern hashtable_t malloc_hashtable;

void add_ignore_func(app_pc pc);
int check_ignore_func(app_pc pc);

void hashtable_del_entry(void *p);


/****************************************************
        T A I N T   M E M   S T R U C T U R E
*****************************************************/
typedef struct _TaintMemStruct
{
  // This one is just used for hash matching.
  uint64_t address[TAINTMAP_NUM][TAINTMAP_SIZE];

  // This one marks taint markings.
  int64_t value[TAINTMAP_NUM][TAINTMAP_SIZE];

} TaintMemStruct;

extern TaintMemStruct taint_mem_;

int mem_taint_is_empty(int index, uint64_t addr);
int mem_taint_find_index(uint64_t addr, int i);
uint64_t mem_taint_get_addr(int index, uint64_t addr);
void    mem_taint_set_addr(int index, uint64_t addr, uint64_t value);
int64_t mem_taint_get_value(int index, uint64_t addr);
void    mem_taint_set_value(int index, uint64_t addr, uint64_t value);


/****************************************************
        T A I N T   R E G   S T R U C T U R E
*****************************************************/

typedef struct _TaintRegStruct
{
  // [which_reg][which_byte]
  int64_t value[16][8];

}  TaintRegStruct;

extern TaintRegStruct taint_reg_;

char     reg_get_byte_value(int reg, int offset);
uint64_t reg_get_full_value(int reg);
int64_t  reg_taint_get_value(int reg, int offset);
void     reg_taint_rm_all(int reg);
int      reg_taint_any(int reg);
int      mem_taint_any(uint64_t mem, int size);
void     mem_taint_rm_all(uint64_t addr, int size);
void     reg_taint_set_value(int reg, int offset, uint64_t value);

void log_instr(instr_t *instr);
instr_t *instr_dupl(instr_t *instr);

reg_t decode_addr(int seg_reg, int base_reg, int index_reg, int scale, int disp, int check_bounds DBG_END_TAINTING_FUNC);
void update_eflags(int opcode, int index, int taint1, int taint2);
void invalidate_eflags();
void clear_eflags();
int is_valid_eflags();
int *get_taint1_eflags();
int *get_taint2_eflags();
int get_eflags_type();

void bound(int *ids, int mask);
void bound2(int *ids1, int *ids2, int mask);
void check_bounds_reg(int reg DBG_END_TAINTING_FUNC);
void check_bounds_mem(uint64_t addr, int size DBG_END_TAINTING_FUNC);
int check_bounds_id(int *ids DBG_END_TAINTING_FUNC);
int solve_ilp(int *ids DBG_END_TAINTING_FUNC);

drsym_info_t *get_func(app_pc pc);
void fix_dest_reg(int dst_reg);
void tid_destruct_hook(void *);


/****************************************************
     U I D / U U I D / I D   H A N D L I N G
*****************************************************/

extern int nextUID;
extern int nextID;
extern int nextIID;

int katu_tid_new_id(int uid);
int katu_tid_new_id_get();
int katu_tid_new_iid(int id, int index);
int katu_tid_new_iid_get();
int katu_tid_new_uid_by_fd(int fd);
int katu_tid_new_uid_by_file(int file);
int katu_tid_new_uid_get();
int katu_tid_copy_id(int id);
int katu_make_id_by_merging_all_ids(int *ids1, int *ids2);
int katu_tid_modify_id_by_symbol(int dst_taint, enum prop_type operation, int src_taint);
void katu_id_add_op(int id, enum prop_type operation, int modify_by);

//
// Function declarations.
//

void dump();
void vulnerability_detected();

// syscalls.
void katu_event_post_syscall(void *drcontext, int id);
bool katu_event_pre_syscall(void *drcontext, int id);
bool katu_syscall_filter(void *drcontext, int sysnum);

// taint.
void katu_taint_by_fd(reg_t addr, unsigned int size, int fd);
void katu_taint_by_file(reg_t addr, unsigned int size, int file);

void katu_taint_wrong(instr_t *instr DBG_END_TAINTING_FUNC);

void katu_taint_mv_2coeffregs2reg(int index_reg, int base_reg, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_neg_reg(int reg DBG_END_TAINTING_FUNC);
void katu_taint_neg_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC);


// Works also if size of source is bigger, just copies necessary part.
void katu_taint_mv_reg2regzx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_reg2regsx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_regbyte2regsx(int src_reg, int src_index, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_mem2regzx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_mem2regsx(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC);
void katu_taint_mv_constmem2reg(uint64 src_addr, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_constmem2regzx(uint64 src_addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC); 
void katu_taint_mv_constmem2regsx(uint64 src_addr, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_constmem2mem(uint64 src_addr, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_constmem2constmem(uint64 src_addr, uint64 dst_addr, uint64_t size DBG_END_TAINTING_FUNC);
void katu_taint_mv_mem2mem(int src_seg_reg, int src_base_reg, int src_index_reg, int src_scale, int src_disp, 
                                  int dst_seg_reg, int dst_base_reg, int dst_index_reg, int dst_scale, int dst_disp, int access_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC);
void katu_taint_mv_reg_rm(int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mv_baseindexmem_rm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC);
void katu_taint_mv_mem_rm(uint64 addr, int size DBG_END_TAINTING_FUNC);

void katu_taint_div_reg(int dividend1_reg, int dividend2_reg, int divisor_reg, int quotinent_reg, int remainder_reg DBG_END_TAINTING_FUNC);
void katu_taint_div_mem(int dividend1_reg, int dividend2_reg, int divisor_seg_reg, int divisor_base_reg, int divisor_index_reg, int divisor_scale, 
                                                 int divisor_disp, int access_size, int quotinent_reg, int remainder_reg DBG_END_TAINTING_FUNC);
void katu_taint_mul_reg2reg(int src1_reg, int src2_reg, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC);
void katu_taint_mul_imm2reg(int src1_reg, int64 value, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC);
void katu_taint_mul_immbyconstmem2reg(int64 value, uint64_t addr, int access_size, int dst_reg DBG_END_TAINTING_FUNC);
void katu_taint_mul_mem2reg(int src1_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int dst1_reg, int dst2_reg DBG_END_TAINTING_FUNC);

void katu_taint_cond_mv_reg2reg(int src_reg, int dst_reg, instr_t *instr, int type DBG_END_TAINTING_FUNC);
void katu_taint_cond_mv_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, instr_t *instr, int type DBG_END_TAINTING_FUNC);

void katu_taint_cond_set_reg(int dst_reg, int type, instr_t *instr DBG_END_TAINTING_FUNC);
void katu_taint_cond_set_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int type, instr_t *instr DBG_END_TAINTING_FUNC);

void katu_taint_cond_jmp(instr_t *instr, int type DBG_END_TAINTING_FUNC);
void katu_taint_ind_jmp_reg(int src_reg DBG_END_TAINTING_FUNC);
void katu_taint_ind_jmp_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size DBG_END_TAINTING_FUNC);

// e.g dst_reg=src_reg+dst_reg, dst_reg=src_reg^dst_reg.....
void katu_taint_mix_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_mix_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC);
void katu_taint_mix_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_mix_constmem2reg(uint64 addr, int dst_reg, int type DBG_END_TAINTING_FUNC); 


void katu_taint_cmp_reg2reg(int reg1, int reg2, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_reg2mem(int reg1, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_reg2constmem(int reg1, uint64_t addr, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_reg2imm(int reg1, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_mem2imm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int size, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_constmem2reg(uint64_t addr, int size, int reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_cmp_constmem2imm(uint64_t addr, int size, int type DBG_END_TAINTING_FUNC);

void katu_taint_cmp_otherinst_reg(int reg DBG_END_TAINTING_FUNC);
void katu_taint_cmp_otherinst_mem(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC);
void katu_taint_cmp_otherinst_constmem(uint64 addr, int access_size DBG_END_TAINTING_FUNC);


void katu_taint_rest_reg2mem(int src_reg, int seg_reg, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC);
void katu_taint_rest_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_rest_mem2reg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int dst_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_rest_imm2reg(uint64_t value, int dst_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_rest_imm2mem(uint64_t value, int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int type DBG_END_TAINTING_FUNC);

void katu_taint_shift_regbyimm(int dst_reg, int64 value, int type DBG_END_TAINTING_FUNC);
void katu_taint_shift_regbyreg(int dst_reg, int src_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_shift_membyreg(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int src_reg, int type DBG_END_TAINTING_FUNC);
void katu_taint_shift_membyimm(int seg_reg, int base_reg, int index_reg, int scale, int disp, int access_size, int64 value, int type DBG_END_TAINTING_FUNC);
void katu_taint_shift_regbyimm_feedreg(int src_reg, int imm, int feed_reg, int type DBG_END_TAINTING_FUNC);

void katu_taint_strcmp_rep(int size DBG_END_TAINTING_FUNC);
void katu_taint_strsto_rep(int size DBG_END_TAINTING_FUNC);
void katu_taint_movs_rep(int size DBG_END_TAINTING_FUNC);
void katu_taint_bswap(int dst_reg DBG_END_TAINTING_FUNC);

void katu_taint_check_ret(uint64_t pc_from DBG_END_TAINTING_FUNC);
void katu_taint_check_jmp_reg(uint64_t pc_from, int reg DBG_END_TAINTING_FUNC);
void katu_taint_check_jmp_mem(uint64_t pc_from, int seg_reg, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC);
void katu_taint_check_jmp_immed(uint64_t pc_from, uint64_t pc DBG_END_TAINTING_FUNC);

// instructions.
dr_emit_flags_t katu_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, 
                                bool translating, void *user_data);
void katu_init_opcodes(void);
void init_ilp(void);
void finish_ilp(void);

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded);
int is_path_secure(const char *path);

void update_bounds_strings_equal(uint64_t saddr, uint64_t daddr, int bytes DBG_END_TAINTING_FUNC);
void memset_reg2mem(int reg, uint64_t mem, int size DBG_END_TAINTING_FUNC);

uint64_t low_trim(uint64_t data, int size);
void get_reg_taint(int reg, int *ids);
void set_reg_taint(int reg, int *ids);
void get_mem_taint(uint64_t addr, int size, int *ids);
void set_mem_taint(uint64_t addr, int size, int *ids);

reg_t get_arg(int arg);

void log_location(app_pc pc);

#ifdef PROCESS_STATISTICS

void katu_taint_statistics(instr_t *instr);

extern int num_strs;
extern int num_cti;
extern int num_cbr;
extern int num_mov;
extern int num_bin;
extern int num_cmp;
extern int num_pp;

#endif

#endif
