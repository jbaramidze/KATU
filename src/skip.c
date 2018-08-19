#define LOGWARNING
#define LOGNORMAL
#define LOGDEBUG
#define LOGDUMP

#include "dr_api.h"
#include "drwrap.h"
#include "core/unix/include/syscall.h"
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nashromi.h"
#include <stddef.h>
#include <ctype.h>

static uint64_t *string_args[10];
static int num_string_args;

typedef struct {
  const char *s1, *s2;
  void *v1, *v2;
  long long i1, i2;
  int ids[8];
  int should;

} arg_data_struct;

arg_data_struct arg_data;

static reg_t get_stack_arg(dr_mcontext_t *ctx, uint arg)
{
    return *((reg_t *) (reg_get_value(DR_REG_RSP, ctx) + (arg - 6 + 1) * sizeof(reg_t)));
}

static reg_t get_arg_reg(int arg, int size)
{
  switch(arg)
  {
    case 0: return reg_resize_to_opsz(DR_REG_RDI, opnd_size_from_bytes(size));
    case 1: return reg_resize_to_opsz(DR_REG_RSI, opnd_size_from_bytes(size));
    case 2: return reg_resize_to_opsz(DR_REG_RDX, opnd_size_from_bytes(size));
    case 3: return reg_resize_to_opsz(DR_REG_RCX, opnd_size_from_bytes(size));
    case 4: return reg_resize_to_opsz(DR_REG_R8,  opnd_size_from_bytes(size));
    case 5: return reg_resize_to_opsz(DR_REG_R9,  opnd_size_from_bytes(size));

    default: FAIL();
  }
}

static reg_t get_ret()
{
  GET_CONTEXT();

  return  reg_get_value(DR_REG_RAX, &mcontext);
}

reg_t get_arg(int arg)
{
  GET_CONTEXT();

  switch(arg)
  {
    case 0: return  reg_get_value(DR_REG_RDI, &mcontext);
    case 1: return  reg_get_value(DR_REG_RSI, &mcontext);
    case 2: return  reg_get_value(DR_REG_RDX, &mcontext);
    case 3: return  reg_get_value(DR_REG_RCX, &mcontext);
    case 4: return  reg_get_value(DR_REG_R8, &mcontext);
    case 5: return  reg_get_value(DR_REG_R9, &mcontext);
    default: return get_stack_arg(&mcontext, arg);
  }

  return 0;
}

// Used to taint env vars.
static void taint_str(const char *str)
{
  int size = strlen(str);

  LTEST("SKIPPER:\t\tTainting string at %p, %d bytes.\n", str, size);

  nshr_taint_by_fd((reg_t) str, size, 0);
}

/*
  Return 0 for strings, -1 for don't taint.
  Not tainting: '%n', floating points.
*/
static int get_format_size(const char *format, int *advance)
{
  int remaining = strlen(format);

  // %[some_stuff]
  if (format[0] == '[')
  {
    // If ] immediatelly follows [, it's in subset.
    int i = 2;

    while (format[i] != ']') i++;

    *advance = i;

    return 0;
  }

  // %l[some_stuff]
  if (format[0] == 'l' && format[1] == '[')
  {
    // If ] immediatelly follows [, it's in subset.
    int i = 3;

    while (format[i] != ']') i++;

    *advance = i;

    return 0;
  }

  *advance = -1;

  if (remaining >= 3)
  {
    if (strncmp(format, "hhd", 3) == 0) { *advance = 3; return sizeof(signed char); }
    if (strncmp(format, "hhi", 3) == 0) { *advance = 3; return sizeof(signed char); }
    if (strncmp(format, "hhu", 3) == 0) { *advance = 3; return sizeof(unsigned char); }
    if (strncmp(format, "hho", 3) == 0) { *advance = 3; return sizeof(unsigned char); }
    if (strncmp(format, "hhx", 3) == 0) { *advance = 3; return sizeof(unsigned char); }
    if (strncmp(format, "hhn", 3) == 0) { *advance = 3; return -1; }


    if (strncmp(format, "lld", 3) == 0) { *advance = 3; return sizeof(long long int); }
    if (strncmp(format, "lli", 3) == 0) { *advance = 3; return sizeof(long long int); }
    if (strncmp(format, "llu", 3) == 0) { *advance = 3; return sizeof(unsigned long long int); }
    if (strncmp(format, "llo", 3) == 0) { *advance = 3; return sizeof(unsigned long long int); }
    if (strncmp(format, "llx", 3) == 0) { *advance = 3; return sizeof(unsigned long long int); }
    if (strncmp(format, "lln", 3) == 0) { *advance = 3; return -1; }
  }

  if (*advance == -1 && remaining >= 2)
  {
    if (strncmp(format, "hd", 2) == 0) { *advance = 2; return sizeof(short int); }
    if (strncmp(format, "hi", 2) == 0) { *advance = 2; return sizeof(short int); }
    if (strncmp(format, "hu", 2) == 0) { *advance = 2; return sizeof(unsigned short int); }
    if (strncmp(format, "ho", 2) == 0) { *advance = 2; return sizeof(unsigned short int); }
    if (strncmp(format, "hx", 2) == 0) { *advance = 2; return sizeof(unsigned short int); }
    if (strncmp(format, "hn", 2) == 0) { *advance = 2; return -1; }


    if (strncmp(format, "ld", 2) == 0) { *advance = 2; return sizeof(long int); }
    if (strncmp(format, "li", 2) == 0) { *advance = 2; return sizeof(long int); }
    if (strncmp(format, "lu", 2) == 0) { *advance = 2; return sizeof(unsigned long int); }
    if (strncmp(format, "lo", 2) == 0) { *advance = 2; return sizeof(unsigned long int); }
    if (strncmp(format, "lx", 2) == 0) { *advance = 2; return sizeof(unsigned long int); }
    if (strncmp(format, "lf", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "le", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "lg", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "la", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "lc", 2) == 0) { *advance = 2; return sizeof(wchar_t); }
    if (strncmp(format, "ls", 2) == 0) { *advance = 2; return 0; }
    if (strncmp(format, "ln", 2) == 0) { *advance = 2; return -1; }


    if (strncmp(format, "jd", 2) == 0) { *advance = 2; return sizeof(intmax_t); }
    if (strncmp(format, "ji", 2) == 0) { *advance = 2; return sizeof(intmax_t); }
    if (strncmp(format, "ju", 2) == 0) { *advance = 2; return sizeof(uintmax_t); }
    if (strncmp(format, "jo", 2) == 0) { *advance = 2; return sizeof(uintmax_t); }
    if (strncmp(format, "jx", 2) == 0) { *advance = 2; return sizeof(uintmax_t); }
    if (strncmp(format, "jn", 2) == 0) { *advance = 2; return -1; }


    if (strncmp(format, "zd", 2) == 0) { *advance = 2; return sizeof(size_t); }
    if (strncmp(format, "zi", 2) == 0) { *advance = 2; return sizeof(size_t); }
    if (strncmp(format, "zu", 2) == 0) { *advance = 2; return sizeof(size_t); }
    if (strncmp(format, "zo", 2) == 0) { *advance = 2; return sizeof(size_t); }
    if (strncmp(format, "zx", 2) == 0) { *advance = 2; return sizeof(size_t); }
    if (strncmp(format, "zn", 2) == 0) { *advance = 2; return -1; }


    if (strncmp(format, "td", 2) == 0) { *advance = 2; return sizeof(ptrdiff_t); }
    if (strncmp(format, "ti", 2) == 0) { *advance = 2; return sizeof(ptrdiff_t); }
    if (strncmp(format, "tu", 2) == 0) { *advance = 2; return sizeof(ptrdiff_t); }
    if (strncmp(format, "to", 2) == 0) { *advance = 2; return sizeof(ptrdiff_t); }
    if (strncmp(format, "tx", 2) == 0) { *advance = 2; return sizeof(ptrdiff_t); }
    if (strncmp(format, "tn", 2) == 0) { *advance = 2; return -1; }


    if (strncmp(format, "Lf", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "Le", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "Lg", 2) == 0) { *advance = 2; return -1; }
    if (strncmp(format, "La", 2) == 0) { *advance = 2; return -1; }
  }

  if (*advance == -1 && remaining >= 1)
  {
    if (format[0] == 'd') { *advance = 1; return sizeof(int); }
    if (format[0] == 'i') { *advance = 1; return sizeof(int); }
    if (format[0] == 'u') { *advance = 1; return sizeof(unsigned int); }
    if (format[0] == 'o') { *advance = 1; return sizeof(unsigned int); }
    if (format[0] == 'x') { *advance = 1; return sizeof(unsigned int); }
    if (format[0] == 'f') { *advance = 1; return -1; }
    if (format[0] == 'e') { *advance = 1; return -1; }
    if (format[0] == 'g') { *advance = 1; return -1; }
    if (format[0] == 'a') { *advance = 1; return -1; }
    if (format[0] == 'c') { *advance = 1; return sizeof(char); }
    if (format[0] == 's') { *advance = 1; return 0; }
    if (format[0] == 'p') { *advance = 1; return sizeof(void *); }
    if (format[0] == 'n') { *advance = 1; return -1; }
  }

  FAIL();

  return -1;
}

static void pre_scanf(DBG_END_TAINTING_FUNC_ALONE)
{
  int num_arg = 1;
  num_string_args = 0;

  const char *format = (const char *) get_arg(0);

  LTEST("SKIPPER:\t\tGoing into scanf with %s.\n", format);

  for (unsigned int i = 0; i < strlen(format) - 1; i++)
  {
    if (format[i] == '%')
    {
      if (format[i+1] == '%')
      {
        i++;
        continue;
      }

      if (format[i+1] == '*')
      {
        num_arg++;
        i++;
      }

      // ignore width specifier.
      while(isdigit(format[i+1]))
      {
        i++;
      }

      int proceed_by;

      int size = get_format_size(format + i + 1, &proceed_by);

      if (size == 0)
      {
        string_args[num_string_args++] = (uint64_t *) get_arg(num_arg);
      }
      else if (size == -1)
      {
        i+= proceed_by;

        FAIL();
      }
      else
      {
        nshr_taint_by_fd(get_arg(num_arg), size, 0);
      }

      num_arg++;
    }
  }

  started_ = MODE_IN_LIBC;
}

static void post_scanf(DBG_END_TAINTING_FUNC_ALONE)
{
  for (int i = 0; i < num_string_args; i++)
  {
    const char *str = (const char *) string_args[i];

    taint_str(str);
  }
}

static void recv_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.i1 = (long long) get_arg(0);
  arg_data.s1 = (const char *)    get_arg(1);
}

static void recv_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int r = get_ret();  

  if (r > 0)
  {
    nshr_taint_by_fd((reg_t) arg_data.s1, r, fds_[arg_data.i1]);
  }
}

static void connect_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  int r = (long long) get_arg(0);

  struct sockaddr_in *addr_in = (struct sockaddr_in *) get_arg(1);

  char *str = inet_ntoa(addr_in->sin_addr);

  LTEST("SKIPPER:\t\tConnected to %s.\n", str);

  fds_history_[fds_[r]].path = strdup(str);
  fds_history_[fds_[r]].secure = 0;  // FIXME: add checking ips.

}

static void accept_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.v1 = (void *) get_arg(1);
}

static void accept_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int r = get_ret();

  fds_[r] = fds_history_index_++;

  if (fds_history_index_ >= MAX_FILE_HISTORY)
  {
    FAIL();
  }

  if (arg_data.v1 != NULL)
  {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) arg_data.v1;

    char *str = inet_ntoa(addr_in->sin_addr);

    LTEST("SKIPPER:\t\tAccepted socket from %s.\n", str);

    fds_history_[fds_[r]].path = strdup(str);
  }
  else
  {
    LTEST("SKIPPER:\t\tAccepted socket from unknown address.\n");

    fds_history_[fds_[r]].path = NULL;
  }

  fds_history_[fds_[r]].secure = 0;  // FIXME: add checking ips.
}

static void ncmp_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
  arg_data.s2 = (const char *) get_arg(1);
  arg_data.i1 = (long long) get_arg(2);
}

static void ncmp_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int t = get_ret();

  if (t == 0)
  {
    update_bounds_strings_equal((uint64_t) arg_data.s1, (uint64_t) arg_data.s2, arg_data.i1 DGB_END_CALL_ARG);
  }
}

static void strcmp_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
  arg_data.s2 = (const char *) get_arg(1);
}

static void strcmp_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int t = get_ret();

  if (t == 0)
  {
    update_bounds_strings_equal((uint64_t) arg_data.s1, (uint64_t) arg_data.s2, strlen(arg_data.s1) DGB_END_CALL_ARG);
  }
}


// TODO: test those
static void strdup_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
}

static void strdup_end(DBG_END_TAINTING_FUNC_ALONE)
{  
  char *dst = (char *) get_ret();

  if (!hashtable_add(&malloc_hashtable, dst, (void *) strlen(dst) + 1))
  {
    FAIL();
  }

  if (dst != NULL)
  {
    nshr_taint_mv_constmem2constmem((uint64) arg_data.s1, (uint64) dst, strlen(dst) DGB_END_CALL_ARG);
  }
}


static void toupper_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  int reg = get_arg_reg(0, sizeof(int));

  get_reg_taint(reg, arg_data.ids);
}

static void toupper_end(DBG_END_TAINTING_FUNC_ALONE)
{
  // Taint output reg with same taints.
  set_reg_taint(DR_REG_RAX, arg_data.ids);
}

static void memset_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);

  // we need to get byte, even thought it's int.
  int src_reg = get_arg_reg(1, 1);

  int n = (int)  get_arg(2);

  memset_reg2mem(src_reg, (uint64_t) dst, n DGB_END_CALL_ARG);
}

static void memmove_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);
  void *src = (void *) get_arg(1);
  unsigned int size  = (int) get_arg(2);
  
  int size_reg = get_arg_reg(2, sizeof(size_t));
  check_bounds_reg(size_reg DGB_END_CALL_ARG);

  // copy to new location first
  int *tmp = (int *) malloc(size);

  nshr_taint_mv_constmem2constmem((uint64) src, (uint64) tmp, size DGB_END_CALL_ARG);
  nshr_taint_mv_constmem2constmem((uint64) tmp, (uint64) dst, size DGB_END_CALL_ARG);

  free(tmp);
}

static void memcpy_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);
  void *src = (void *) get_arg(1);
  unsigned int size  = (int) get_arg(2);

  int size_reg = get_arg_reg(2, sizeof(size_t));

  check_bounds_reg(size_reg DGB_END_CALL_ARG);

  nshr_taint_mv_constmem2constmem((uint64) src, (uint64) dst, size DGB_END_CALL_ARG);
}

static void strcpy_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);
  void *src = (void *) get_arg(1);

  unsigned int size = strlen(src);

  nshr_taint_mv_constmem2constmem((uint64) src, (uint64) dst, size DGB_END_CALL_ARG);
}

static void strncpy_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);
  void *src = (void *) get_arg(1);
  unsigned int size  = (int) get_arg(2);

  unsigned int len = strlen(src);

  // choose smallest in size.
  if (size > len)
  {
    size = len;
  }

  nshr_taint_mv_constmem2constmem((uint64) src, (uint64) dst, size DGB_END_CALL_ARG);
}

static void read_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.i1 = (int)          get_arg(0);
  arg_data.s1 = (const char *) get_arg(1);
}

static void read_end(DBG_END_TAINTING_FUNC_ALONE)
{
  uint64_t r = (uint64_t) get_ret();

  if (r > 0)
  {
    nshr_taint_by_fd((reg_t) arg_data.s1, r, fds_[arg_data.i1]);
  }
}

static void fclose_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *v = (void *) get_arg(0);

  if (!hashtable_remove(&FILEs_, v))
  {
    FAIL();
  }
}

static void fgets_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
  arg_data.v1 = (void *)       get_arg(2);
}

static void fgets_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int size = strlen(arg_data.s1);

  if (size > 0)
  {
    int *f = (int *) hashtable_lookup(&FILEs_, arg_data.v1);

    if (f == NULL) FAIL();

    int index = *f;

    nshr_taint_by_file((reg_t) arg_data.s1, size, index);
  }
}

static void fread_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
  arg_data.v1 = (void *)       get_arg(3);
}

static void fread_end(DBG_END_TAINTING_FUNC_ALONE)
{
  uint64_t r = (uint64_t) get_ret();

  if (r > 0)
  {
    int *f = (int *) hashtable_lookup(&FILEs_, arg_data.v1);

    if (f == NULL) FAIL();

    int index = *f;

    nshr_taint_by_file((reg_t) arg_data.s1, r, index);
  }
}

static void taint_ret_by_stdin(DBG_END_TAINTING_FUNC_ALONE)
{
  int newid = nshr_tid_new_uid_by_fd(0);

  int ids[1];

  ids[0] = newid;

  set_reg_taint(DR_REG_AL, ids);
}

static void atoi_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  const char *s = (const char *) get_arg(0);

  // Check if first char in string is tainted.
  int index = mem_taint_find_index((uint64_t) s, 0);
  int id    = MEMTAINTVAL(index, (uint64_t) s);

  if (id > 0)
  {
    arg_data.should = 1;

    // Also we need copy of uid to create new ids for integer.
    arg_data.i1 = ID2UID(id);
  }
  else
  {
    arg_data.should = 0;
  }
}

static void atoi_end(DBG_END_TAINTING_FUNC_ALONE)
{
  if (arg_data.should)
  {
    LTEST("SKIPPER:\t\tTainting EAX by uid %d.\n", arg_data.i1);

    // We should create new ids from uid and taint EAX.
    for (unsigned int i = 0; i < REGSIZE(DR_REG_EAX); i++)
    {
      int newid = nshr_tid_new_id(arg_data.i1);
      SETREGTAINTVAL(DR_REG_EAX, i, newid);
    }
  }
}

static void strtol_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  const char *s = (const char *) get_arg(0);
  uint64_t endptr = (uint64_t ) get_arg(1);

  // Detaint location pointed by endptr.
  for (int i = 0; i < 8; i++)
  {
    int index = mem_taint_find_index(endptr, i);

    MEMTAINTRM(index, endptr + i);
  }

  // Check if first char in string is tainted.
  int index = mem_taint_find_index((uint64_t) s, 0);
  int id    = MEMTAINTVAL(index, (uint64_t) s);

  if (id > 0)
  {
    arg_data.should = 1;

    // Also we need copy of uid to create new ids for integer.
    arg_data.i1 = ID2UID(id);
  }
  else
  {
    arg_data.should = 0;
  }
}

static void strtol_end(DBG_END_TAINTING_FUNC_ALONE)
{
  if (arg_data.should)
  {
    LTEST("SKIPPER:\t\tTainting EAX by uid %d.\n", arg_data.i1);

    // We should create new ids from uid and taint EAX.
    for (unsigned int i = 0; i < REGSIZE(DR_REG_EAX); i++)
    {
      int newid = nshr_tid_new_id(arg_data.i1);
      SETREGTAINTVAL(DR_REG_EAX, i, newid);
    }
  }
}

static void fopen_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.s1 = (const char *) get_arg(0);
}

static void fopen_end(DBG_END_TAINTING_FUNC_ALONE)
{
  void *r = (void *) get_ret();

  LTEST("SKIPPER:\t\tFOpened %s at %p.\n", arg_data.s1, r);

  files_history_[files_history_index_].path = strdup(arg_data.s1);
  files_history_[files_history_index_].secure = is_path_secure(arg_data.s1);

  int *e = (int *) malloc(sizeof(int));

  *e = files_history_index_++;

  if (files_history_index_ >= MAX_FILE_HISTORY)
  {
    FAIL();
  }

  if (!hashtable_add(&FILEs_, r, (void *) e))
  {
    FAIL();
  }
}

static void open_end(DBG_END_TAINTING_FUNC_ALONE)
{
  int r = (int) get_ret();

  LTEST("SKIPPER:\t\tOpened %s at FD#%d.\n", arg_data.s1, r);

  fds_[r] = fds_history_index_++;

  if (fds_history_index_ >= MAX_FILE_HISTORY)
  {
    FAIL();
  }

  fds_history_[fds_[r]].secure = is_path_secure(arg_data.s1);
  fds_history_[fds_[r]].path = strdup(arg_data.s1);
}

static void check_arg0_8(DBG_END_TAINTING_FUNC_ALONE)
{
  int reg = get_arg_reg(0, sizeof(size_t));

  check_bounds_reg(reg DGB_END_CALL_ARG);
}

static void check_arg1_8(DBG_END_TAINTING_FUNC_ALONE)
{
  int reg = get_arg_reg(1, sizeof(size_t));

  check_bounds_reg(reg DGB_END_CALL_ARG);
}

static void taint_retstr(DBG_END_TAINTING_FUNC_ALONE)
{
  const char *str = (const char *) get_ret();

  if (str != NULL)
  {
    taint_str(str);
  }
}

// TODO: test those
static void mmap_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.i1 = (int ) get_arg(1); // length
  arg_data.i2 = (int ) get_arg(4); // fd
}

static void mmap_end(DBG_END_TAINTING_FUNC_ALONE)
{
  const char *ret = (const char *) get_ret();

  LTEST("SKIPPER:\t\tTainting string at %p, %d bytes.\n", ret, arg_data.i1);

  nshr_taint_by_fd((reg_t) ret, arg_data.i1, arg_data.i2);
}

static void realloc_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.v1 = (void * ) get_arg(0);
  arg_data.i1 = (int ) get_arg(1);

  // Implementation-defined behaviour
  if (arg_data.v1 == NULL &&  arg_data.i1 == 0)
  {
    FAIL();
  }
}

static void realloc_end(DBG_END_TAINTING_FUNC_ALONE)
{
  char *ret = (char *) get_ret();

  // like free().
  if (arg_data.i1 == 0)
  {
    LDEBUG("SKIPPER:\t\tRealloc freed at %p.\n", arg_data.v1);

    if (!hashtable_remove(&malloc_hashtable, arg_data.v1))
    {
      FAIL();
    }

    return;
  }

  // like malloc().
  if (arg_data.v1 == NULL)
  {
    char *ret = (char *) get_ret();

    if (!hashtable_add(&malloc_hashtable, ret, (void *)arg_data.i1))
    {
      FAIL();
    }

    LDEBUG("SKIPPER:\t\tRealloc allocated %d bytes at %p.\n", arg_data.i1, ret);

    return;
  }

  if (ret == arg_data.v1)
  {
    LDEBUG("SKIPPER:\t\tRealloc extended at %p, by %d bytes.\n", arg_data.v1, arg_data.i1);

    // Just change the value in hashtable.
    if (hashtable_add_replace(&malloc_hashtable, arg_data.v1, (void *) arg_data.i1) == NULL) FAIL();
  }
  else
  {
    // The data was moved!
    uint64_t old_size = (uint64_t) hashtable_lookup(&malloc_hashtable, arg_data.v1);

    LDEBUG("SKIPPER:\t\tRealloc moved from from %p, %d bytes to %p, %d bytes.\n", arg_data.v1, old_size, ret, arg_data.i1);

    // Lookup failure.
    if (old_size == 0) FAIL();

    nshr_taint_mv_constmem2constmem((uint64) arg_data.v1, (uint64) ret, old_size DGB_END_CALL_ARG);

    if (!hashtable_remove(&malloc_hashtable, arg_data.v1))
    {
      FAIL();
    }

    if (!hashtable_add(&malloc_hashtable, ret, (void *)arg_data.i1))
    {
      FAIL();
    }
  }


  #ifdef LOGDUMP
  for (int i = 0; i <  arg_data.i1; i++)
  {
    LDEBUG("SKIPPER:\t\tRealloc'd %p.\n", ret + i);
  }
  #endif
}


static void malloc_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  arg_data.i1 = (int ) get_arg(0);
}

static void malloc_end(DBG_END_TAINTING_FUNC_ALONE)
{
  char *ret = (char *) get_ret();

  LDEBUG("SKIPPER:\t\tMalloc allocated at %p, %d bytes.\n", ret, arg_data.i1);

  if (!hashtable_add(&malloc_hashtable, ret, (void *)arg_data.i1))
  {
    FAIL();
  }

  #ifdef LOGDUMP
  for (int i = 0; i <  arg_data.i1; i++)
  {
    LDEBUG("SKIPPER:\t\tMalloc'd %p.\n", ret + i);
  }
  #endif
}

static void calloc_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  int reg0 = (int ) get_arg(0);
  int reg1 = (int ) get_arg(1);

  arg_data.i1 = reg0 * reg1;
}
static void calloc_end(DBG_END_TAINTING_FUNC_ALONE)
{
  char *ret = (char *) get_ret();

  if (!hashtable_add(&malloc_hashtable, ret, (void *)arg_data.i1))
  {
    FAIL();
  }

  mem_taint_rm_all((uint64_t) ret, arg_data.i1);

  LDEBUG("SKIPPER:\t\tCalloc allocated at %p, %d bytes.\n", ret, arg_data.i1);

  #ifdef LOGDUMP
  for (int i = 0; i <  arg_data.i1; i++)
  {
    LDEBUG("SKIPPER:\t\tCalloc'd %p.\n", ret + i);
  }
  #endif
}

static void free_call(DBG_END_TAINTING_FUNC_ALONE)
{
  void *v = (void*) get_arg(0);

  // Nothing happens on free(NULL)
  if (v == NULL)
  {
    return;
  }

  LDEBUG("SKIPPER:\t\tFree called for %p.\n", v);

  if (!hashtable_remove(&malloc_hashtable, v))
  {
    FAIL();
  }
}


static void restricted_func(DBG_END_TAINTING_FUNC_ALONE)
{
  LERROR("No support for this instruction, exitting....\n");

  FAIL();
}

static void ignore_handlers(const module_data_t *mod, const char *function)
{
  app_pc addr = (app_pc) dr_get_proc_address(mod -> handle, function);

  if (addr == NULL)
  {
    dr_printf("ERROR! Failed getting address for %s.\n", function);

    FAIL();
  }

  handleFunc *e = malloc(sizeof(handleFunc) * 3);
  e[0] = NULL;
  e[1] = NULL;
  e[2] = (handleFunc) strdup(function);

  // Fixme: Don't allocate for all ignore functions same thing. Make one, but deal with deallocation.

  if (!hashtable_add(&func_hashtable, addr, (void *)e))
  {
    FAIL();
  }
}


static void register_handlers(const module_data_t *mod, const char *function,  
                            void(*pre_func_cb)(DBG_END_TAINTING_FUNC_ALONE), 
                                void(*post_func_cb)(DBG_END_TAINTING_FUNC_ALONE))
{
  app_pc addr = (app_pc) dr_get_proc_address(mod -> handle, function);

  if (addr == NULL)
  {
    dr_printf("ERROR! Failed getting address for %s.\n", function);

    FAIL();
  }

  handleFunc *e = malloc(sizeof(handleFunc) * 3);
  e[0] = pre_func_cb;
  e[1] = post_func_cb;
  e[2] = (handleFunc) strdup(function);

  if (!hashtable_add(&func_hashtable, addr, (void *)e))
  {
    FAIL();
  }
}

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
   const char *module = dr_module_preferred_name(mod);

   dr_printf("Info:\t\tLoading %s at 0x%llx.\n", module, mod -> start);

   if (strncmp(dr_module_preferred_name(mod), "libc.so", 7) == 0)
   {
     register_handlers(mod, "scanf", pre_scanf, post_scanf);
     register_handlers(mod, "malloc", malloc_begin, malloc_end);           // void *malloc(size_t size);
     register_handlers(mod, "realloc", realloc_begin, realloc_end);        // void *realloc(void *ptr, size_t size);
     register_handlers(mod, "calloc", calloc_begin, calloc_end);           // void *calloc(size_t nmemb, size_t size);
     register_handlers(mod, "free", free_call, NULL);                      // void free(void *ptr);
     register_handlers(mod, "getenv", NULL, taint_retstr);                 // char *getenv(const char *name);
     register_handlers(mod, "strcmp", strcmp_begin, strcmp_end);           // int strcmp(const char *s1, const char *s2);
     register_handlers(mod, "strcasecmp", strcmp_begin, strcmp_end);       // int strcasecmp(const char *s1, const char *s2);
     register_handlers(mod, "strncmp", ncmp_begin, ncmp_end);              // int strncmp(const char *s1, const char *s2, size_t n);
     register_handlers(mod, "strncasecmp", ncmp_begin, ncmp_end);          // int strncasecmp(const char *s1, const char *s2, size_t n);
     register_handlers(mod, "memcmp", ncmp_begin, ncmp_begin);             // int memcmp(const void *s1, const void *s2, size_t n);
     register_handlers(mod, "strcpy", strcpy_begin, NULL);                 // char *strcpy(char *dest, const char *src);
     register_handlers(mod, "strncpy", strncpy_begin, NULL);               // char *strncpy(char *dest, const char *src, size_t n);
     register_handlers(mod, "__memcpy_chk", memcpy_begin, NULL);           // void *memcpy(void *dest, const void *src, size_t n);
     register_handlers(mod, "memcpy", memcpy_begin, NULL);                 // void *memcpy(void *dest, const void *src, size_t n);
     register_handlers(mod, "memmove", memmove_begin, NULL);               // void *memmove(void *dest, const void *src, size_t n);
     register_handlers(mod, "memset", memset_begin, NULL);                 // void *memset(void *s, int c, size_t n);
     register_handlers(mod, "fopen", fopen_begin, fopen_end);              // FILE *fopen(const char *path, const char *mode);
     register_handlers(mod, "open", fopen_begin, open_end);                // int open(const char *pathname, int flags, mode_t mode);
     register_handlers(mod, "fread", fread_begin, fread_end);              // size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
     register_handlers(mod, "fgets", fgets_begin, fgets_end);              // char *fgets(char *s, int size, FILE *stream);
     register_handlers(mod, "fclose", fclose_begin, NULL);                 // int fclose(FILE *stream);
     register_handlers(mod, "read", read_begin, read_end);                 // ssize_t read(int fd, void *buf, size_t count);
     register_handlers(mod, "pread", read_begin, read_end);                // ssize_t pread(int fd, void *buf, size_t count, off_t offset);
     register_handlers(mod, "accept", accept_begin, accept_end);           // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     register_handlers(mod, "connect", connect_begin, NULL);               // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
     register_handlers(mod, "recv", recv_begin, recv_end);                 // ssize_t recv(int sockfd, void *buf, size_t len, int flags);
     register_handlers(mod, "strtol", strtol_begin, strtol_end);           // long int strtol(const char *nptr, char **endptr, int base);
     register_handlers(mod, "atoi", atoi_begin, atoi_end);                 // int atoi(const char *nptr);
     register_handlers(mod, "toupper", toupper_begin, toupper_end);        // int toupper(int c);
     register_handlers(mod, "tolower", toupper_begin, toupper_end);        // int tolower(int c);
     register_handlers(mod, "strdup", strdup_begin, strdup_end);           // char *strdup(const char *s);
     register_handlers(mod, "qsort", check_arg1_8, NULL);                  // void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
     register_handlers(mod, "mmap", mmap_begin, mmap_end);                 // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
     register_handlers(mod, "getchar", NULL, taint_ret_by_stdin);          // int getchar(void);

     register_handlers(mod, "vfork", restricted_func, NULL);


     ignore_handlers(mod, "rand_r");
     ignore_handlers(mod, "strlen");
     ignore_handlers(mod, "strerror");
     ignore_handlers(mod, "snprintf");
     ignore_handlers(mod, "fwrite");
     ignore_handlers(mod, "fflush");
     ignore_handlers(mod, "fseek");
     ignore_handlers(mod, "lseek");
     ignore_handlers(mod, "fcntl");
     ignore_handlers(mod, "ftell");
     ignore_handlers(mod, "write");
     ignore_handlers(mod, "send");
     ignore_handlers(mod, "close");
     ignore_handlers(mod, "rewind");
     ignore_handlers(mod, "poll");
     ignore_handlers(mod, "sleep");
     ignore_handlers(mod, "shutdown");
     ignore_handlers(mod, "printf");
     ignore_handlers(mod, "fprintf");
     ignore_handlers(mod, "bsd_signal");
     ignore_handlers(mod, "getpid");
     ignore_handlers(mod, "setlocale");
     ignore_handlers(mod, "strchr");
     ignore_handlers(mod, "strstr");
     ignore_handlers(mod, "strrchr");
     ignore_handlers(mod, "getopt");
     ignore_handlers(mod, "getopt_long");
     ignore_handlers(mod, "getuid");
     ignore_handlers(mod, "exit");
     ignore_handlers(mod, "htons");
     ignore_handlers(mod, "inet_addr");
     ignore_handlers(mod, "htonl");
     ignore_handlers(mod, "setsockopt");
     ignore_handlers(mod, "bind");
     ignore_handlers(mod, "listen");
     ignore_handlers(mod, "inet_ntoa");
     ignore_handlers(mod, "gethostbyname");
     ignore_handlers(mod, "socket");    // We care about connect() and accept()
     ignore_handlers(mod, "__errno_location");
     ignore_handlers(mod, "__ctype_b_loc");
     // Problematic one, toupper defined as 
     // return __c >= -128 && __c < 256 ? (*__ctype_toupper_loc ())[__c] : __c;
     ignore_handlers(mod, "__ctype_toupper_loc"); 
     ignore_handlers(mod, "__xstat");
     ignore_handlers(mod, "__fxstat");
     ignore_handlers(mod, "__printf_chk");
     ignore_handlers(mod, "__lxstat");
     ignore_handlers(mod, "_IO_puts");
     ignore_handlers(mod, "wcwidth");
     ignore_handlers(mod, "newlocale");
     ignore_handlers(mod, "uselocale");
     ignore_handlers(mod, "freelocale");
     ignore_handlers(mod, "regcomp");
     ignore_handlers(mod, "regexec");
     ignore_handlers(mod, "regfree");
     ignore_handlers(mod, "iswprint");
     ignore_handlers(mod, "iconv");
     ignore_handlers(mod, "iconv_open");
     ignore_handlers(mod, "iconv_close");
     ignore_handlers(mod, "getcwd");
     ignore_handlers(mod, "fputs");
     ignore_handlers(mod, "fputc");
     ignore_handlers(mod, "memchr");
     ignore_handlers(mod, "strspn");
     ignore_handlers(mod, "strcspn");
     ignore_handlers(mod, "getpagesize");
     ignore_handlers(mod, "feof");
     ignore_handlers(mod, "strpbrk");



     // Ignoring some precision here, TODO for future:
     // think if we can improve it.
     ignore_handlers(mod, "asprintf");
     ignore_handlers(mod, "sprintf");
     ignore_handlers(mod, "vsnprintf");
     ignore_handlers(mod, "vasprintf");
     ignore_handlers(mod, "mbrtowc");
     ignore_handlers(mod, "unlink");
     ignore_handlers(mod, "glob");
     ignore_handlers(mod, "globfree");
     
   }
   else if (strncmp(dr_module_preferred_name(mod), "ld-linux-x86-64.so", 18) == 0)
   {
   }
   else if (strncmp(dr_module_preferred_name(mod), "libcrypto", 9) == 0)
   {
   }
   else if (strncmp(dr_module_preferred_name(mod), "libssl", 6) == 0)
   {
      app_pc addr = (app_pc) dr_get_proc_address(mod -> handle, "SSL_connect");
      add_ignore_func(addr);
      addr = (app_pc) dr_get_proc_address(mod -> handle, "SSL_accept");
      add_ignore_func(addr);
      addr = (app_pc) dr_get_proc_address(mod -> handle, "tls1_enc");
      add_ignore_func(addr);
   }
}