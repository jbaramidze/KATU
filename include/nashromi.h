#ifndef THESIS_MODULE_H
#define THESIS_MODULE_H

#include <stdint.h>

// Do additional checks, while testing
#define CHECKS

// Pass instruction among other params when tainting, to debug.
#define DBG_PASS_INSTR

#ifdef DBG_PASS_INSTR

  #define DBG_TAINT_NUM_PARAMS(x) (x+1)
  #define DGB_END_CALL_ARG , instr
  #define DBG_END_DR_CLEANCALL , OPND_CREATE_INT64(instr_dupl(instr))
  #define DBG_END_TAINTING_FUNC , instr_t *instr
  #define DBG_END_TAINTING_FUNC_ALONE instr_t *instr
  
  extern instr_t *instr_pointers[1024*16];
  extern int instr_next_pointer;
  
  
  /*
  Specific logging functions.
  */
  
  #if defined LOGDEBUG
  #define LDEBUG_TAINT(A, ...) { log_instr(instr); dr_printf(__VA_ARGS__); }
  #elif defined LOGTEST
  #define LDEBUG_TAINT(A, ...) if (A) { log_instr(instr); dr_printf(__VA_ARGS__); }
  #else
  #define LDEBUG_TAINT(A, ...)
  #endif
  
  #if defined LOGDUMP
  #define LDUMP_TAINT(i, A, ...) { log_instr(instr); dr_printf(__VA_ARGS__); }
  #elif defined LOGTEST
  #define LDUMP_TAINT(i, A, ...) if ((A) && i == 0) { log_instr(instr); dr_printf(__VA_ARGS__); }
  #else
  #define LDUMP_TAINT(i, A, ...)
  #endif


#else

  #define DBG_TAINT_NUM_PARAMS(x) (x)
  #define DGB_END_CALL_ARG 
  #define DBG_END_DR_CLEANCALL
  #define DBG_END_TAINTING_FUNC
  #define DBG_END_TAINTING_FUNC_ALONE
  
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

#endif

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
  // MOV's
  PROP_MOV,
  PROP_MOVZX,
  PROP_MOVSX,
  // Binaries
  PROP_ADD,
  PROP_SUB,
  PROP_ADC,
  PROP_SBB,
  PROP_IMUL,
  // Restrictors
  PROP_OR,
  PROP_XOR,
  PROP_AND,
  // Others
  PROP_CMP

};


static const char *PROP_NAMES[] = {
    "mov", "movzx", "movsx", 
    "add", "sub", "add with carry", "sub with borrow", "imul", 
    "or", "and", "xor"
};

int is_binary(enum prop_type type );
int is_mov(enum prop_type type );
int is_restrictor(enum prop_type type );

void update_eflags(int opcode);


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

typedef struct {
  int last_affecting_opcode;

} Eflags;



//
// Utility definitions.
//

#ifndef MIN
# define MIN(x, y) ((x) <= (y) ? (x) : (y))
#endif

#define STOP_IF_NOT_ACTIVE(retval)    if (started_ != MODE_ACTIVE)  {  return retval;  }
#define STOP_IF_IGNORING(retval)    if (started_ == MODE_IGNORING)  {  return retval;  }
#define UNUSED(expr) 			do { (void)(expr); } while (0)

#define FAIL() { dr_printf("FAIL! at %s:%d.\n", __FILE__, __LINE__); \
                   dump(); \
                 				exit(-1); }

#define GET_CONTEXT()			dr_mcontext_t mcontext = {sizeof(mcontext),DR_MC_ALL}; \
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

#define REGTAINTVAL1(reg, offset)                   reg_taint_get_value(reg, offset, 0) 
#define REGTAINTVAL2(reg, offset)                   reg_taint_get_value(reg, offset, 1) 
#define REGTAINTVAL4(reg, offset)                   reg_taint_get_value(reg, offset, 2) 
#define REGTAINTVAL8(reg, offset)                   reg_taint_get_value(reg, offset, 3)
#define REGTAINTVAL(reg, offset, size)              reg_taint_get_value(reg, offset, size)
#define SETREGTAINTVAL(reg, offset, size, value)    reg_taint_set_value(reg, offset, size, value)


#define REGTAINTVALS_LOG(reg, offset)       reg_taint_get_value(reg, offset, 0), reg_taint_get_value(reg, offset, 1), reg_taint_get_value(reg, offset, 2), reg_taint_get_value(reg, offset, 3)
#define MEMTAINTVALS_LOG(index, address)    mem_taint_get_value(index, address, 0), mem_taint_get_value(index, address, 1), mem_taint_get_value(index, address, 2), mem_taint_get_value(index, address, 3)
 
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

#ifdef LOGWARNING
#define LWARNING(...) dr_printf(__VA_ARGS__)
#else
#define LWARNING(...) 
#endif


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


//
// Global variables.
//


extern enum mode started_;

extern Eflags eflags_;

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
uint64_t mem_taint_get_addr(int index, uint64_t addr);
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

void log_instr(instr_t *instr);
instr_t *instr_dupl(instr_t *instr);


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
int nshr_tid_modify_id_by_symbol(int dst_taint, int byte, enum prop_type operation, int src_taint);

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

void nshr_taint_mv_2coeffregs2reg(int index_reg, int base_reg, int dst_reg DBG_END_TAINTING_FUNC);
void nshr_taint_mv_reg2reg(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);

// Works also if size of source is bigger, just copies necessary part.
void nshr_taint_mv_reg2regzx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);
void nshr_taint_mv_reg2regsx(int src_reg, int dst_reg DBG_END_TAINTING_FUNC);
void nshr_taint_mv_mem2reg(int segment, int base_reg, int index_reg, int scale, int disp, int dest_reg DBG_END_TAINTING_FUNC);
void nshr_taint_mv_mem2regzx(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC);
void nshr_taint_mv_mem2regsx(int segment, int base_reg, int index_reg, int scale, int disp, int dst_reg, int extended_from_size DBG_END_TAINTING_FUNC);
void nshr_taint_mv_reg2mem(int src_reg, int segment, int base_reg, int index_reg, int scale, int disp DBG_END_TAINTING_FUNC);
void nshr_taint_mv_constmem2reg(uint64 addr, int dst_reg DBG_END_TAINTING_FUNC); 
void nshr_taint_mv_reg2constmem(int src_reg, uint64 addr DBG_END_TAINTING_FUNC); 
void nshr_taint_mv_reg_rm(int dst_reg DBG_END_TAINTING_FUNC);
void nshr_taint_mv_baseindexmem_rm(int segment, int base_reg, int index_reg, int scale, int disp, int access_size DBG_END_TAINTING_FUNC);
void nshr_taint_mv_mem_rm(uint64 addr, int size DBG_END_TAINTING_FUNC);

void nshr_taint_jmp(DBG_END_TAINTING_FUNC_ALONE);
void nshr_taint_cmp(DBG_END_TAINTING_FUNC_ALONE);

// e.g dst_reg=src_reg+dst_reg, dst_reg=src_reg^dst_reg.....
void nshr_taint_mix_reg2reg(int src_reg, int dst_reg, int type DBG_END_TAINTING_FUNC);
void nshr_taint_mix_reg2mem(int src_reg, int segment, int base_reg, int index_reg, int scale, int disp, int type DBG_END_TAINTING_FUNC);
void nshr_taint_mix_mem2reg(int segment, int base_reg, int index_reg, int scale, int disp, int dest_reg, int type DBG_END_TAINTING_FUNC);


void nshr_taint_ret(DBG_END_TAINTING_FUNC_ALONE);
void nshr_taint_jmp_reg(int dst_reg DBG_END_TAINTING_FUNC);

// instructions.
dr_emit_flags_t nshr_event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, 
	                              bool translating, void *user_data);
void nshr_init_opcodes(void);

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data);
void nshr_post_scanf(void *wrapcxt, void *user_data);


#endif
