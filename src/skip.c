#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "drwrap.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"
#include <stddef.h>

static uint64_t *string_args[10];
static int num_string_args;

/*
  Return 0 for strings, -1 for don't taint.
  Not tainting: '%n', floating points.
*/
int get_format_size(const char *format, int *advance)
{
  int remaining = strlen(format);

  dr_printf("Starting get_format_size with %c and rem %d.\n", format[0], remaining);

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
}

void nshr_pre_scanf(void *wrapcxt, OUT void **user_data)
{
  num_string_args = 1;

  const char *format = (const char *) drwrap_get_arg(wrapcxt, 0);

  LTEST("DRWRAP:\t\tGoing into scanf with %s.\n", format);

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
        num_string_args++;
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
  	  	// Deal with string.

  	  	FAIL();
  	  }
  	  else if (size == -1)
  	  {
  	  	i+= proceed_by;

        num_string_args++;

        FAIL();
  	  }
  	  else
  	  {
        void *f = drwrap_get_arg(wrapcxt, num_string_args);
        
        nshr_taint((reg_t) f, size, 0);

        num_string_args++;
  	  }
  	}
  }

  started_ = MODE_IN_LIBC;
}

void nshr_post_scanf(void *wrapcxt, void *user_data)
{

}