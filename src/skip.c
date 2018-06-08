#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "drwrap.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"
#include <stddef.h>
#include <ctype.h>

static uint64_t *string_args[10];
static int num_string_args;

typedef struct {
  const char *s1, *s2;
  void *v1, *v2;
  long long i1, i2;
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

static reg_t get_arg(int arg)
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

static void memset_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);

  // we need to get byte, even thought it's int.
  int src_reg = get_arg_reg(1, 1);

  int n = (int)  get_arg(2);

  memset_reg2mem(src_reg, (uint64_t) dst, n DGB_END_CALL_ARG);
}

static void memcpy_begin(DBG_END_TAINTING_FUNC_ALONE)
{
  void *dst = (void *) get_arg(0);
  void *src = (void *) get_arg(1);
  unsigned int size  = (int) get_arg(2);

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
    nshr_taint_by_file((reg_t) arg_data.s1, r, arg_data.v1);
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
      SETREGTAINTVAL(DR_REG_EAX, i, nshr_tid_new_id(arg_data.i1));
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

  LTEST("SKIPPER:\t\tOpened %s at %p.\n", arg_data.s1, r);

  char *e = (char *) malloc(sizeof(char) * (strlen(arg_data.s1) + 1));

  strcpy(e, arg_data.s1);

  if (!hashtable_add(&FILEs_, r, (void *)e))
  {
    FAIL();
  }
}

static void check_arg0_8(DBG_END_TAINTING_FUNC_ALONE)
{
  int reg = get_arg_reg(0, sizeof(size_t));

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

static void ignore_handlers(const module_data_t *mod, const char *function)
{
  app_pc addr = (app_pc) dr_get_proc_address(mod -> handle, function);

  if (addr == NULL)
  {
    dr_printf("ERROR! Failed getting address for %s.\n", function);

    FAIL();
  }

  handleFunc *e = malloc(sizeof(handleFunc) * 2);
  e[0] = NULL;
  e[1] = NULL;

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

  handleFunc *e = malloc(sizeof(handleFunc) * 2);
  e[0] = pre_func_cb;
  e[1] = post_func_cb;

  if (!hashtable_add(&func_hashtable, addr, (void *)e))
  {
    FAIL();
  }
}

void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
   const char *module = dr_module_preferred_name(mod);

   dr_printf("Info:\t\tLoading %s.\n", module);

   if (strncmp(dr_module_preferred_name(mod), "libc.so", 7) == 0)
   {
     register_handlers(mod, "scanf", pre_scanf, post_scanf);
     register_handlers(mod, "malloc", check_arg0_8, NULL);                 // void *malloc(size_t size);
     register_handlers(mod, "getenv", NULL, taint_retstr);                 // char *getenv(const char *name);
     register_handlers(mod, "strcmp", strcmp_begin, strcmp_end);           // int strcmp(const char *s1, const char *s2);
     register_handlers(mod, "strncmp", ncmp_begin, ncmp_end);              // int strncmp(const char *s1, const char *s2, size_t n);
     register_handlers(mod, "memcmp", ncmp_begin, ncmp_begin);             // int memcmp(const void *s1, const void *s2, size_t n);
     register_handlers(mod, "strcpy", strcpy_begin, NULL);                 // char *strcpy(char *dest, const char *src);
     register_handlers(mod, "strncpy", strncpy_begin, NULL);               // char *strncpy(char *dest, const char *src, size_t n);
     register_handlers(mod, "__memcpy_chk", memcpy_begin, NULL);           // void *memcpy(void *dest, const void *src, size_t n);
     register_handlers(mod, "memcpy", memcpy_begin, NULL);                 // void *memcpy(void *dest, const void *src, size_t n);
     register_handlers(mod, "memset", memset_begin, NULL);                 // void *memset(void *s, int c, size_t n);
     register_handlers(mod, "fopen", fopen_begin, fopen_end);              // FILE *fopen(const char *path, const char *mode);
     register_handlers(mod, "fread", fread_begin, fread_end);              // size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
     register_handlers(mod, "strtol", strtol_begin, strtol_end);           // long int strtol(const char *nptr, char **endptr, int base);


     ignore_handlers(mod, "__printf_chk");

     // Problematic one, toupper defined as 
     // return __c >= -128 && __c < 256 ? (*__ctype_toupper_loc ())[__c] : __c;
     ignore_handlers(mod, "__ctype_toupper_loc"); 
     ignore_handlers(mod, "__xstat");
     ignore_handlers(mod, "_IO_puts");
     ignore_handlers(mod, "rand_r");
     ignore_handlers(mod, "strlen");
     ignore_handlers(mod, "snprintf");
     ignore_handlers(mod, "fclose");
     ignore_handlers(mod, "free");
     



   }
   else if (strncmp(dr_module_preferred_name(mod), "ld-linux-x86-64.so", 18) == 0)
   {
   }
}