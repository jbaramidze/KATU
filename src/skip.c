#define LOGWARNING
#define LOGTEST
#define LOGDEBUG
#undef LOGDUMP

#include "dr_api.h"
#include "core/unix/include/syscall.h"
#include "nashromi.h"



static uint64_t *string_args[10];
static int num_string_args;

int get_format_size(const char *format, int *advance)
{
  int remaining = strlen(format);

  dr_printf("Starting get_format_size with %c and rem %d.\n", format[0], remaining);

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

  	  /*if (format[i+1] == 'd')
  	  {
  	  	dr_printf("gotcha!.\n\n\n");

        int *f = (int *) drwrap_get_arg(wrapcxt, num_string_args);

        nshr_taint((reg_t) &f, 4, 0);
  	  }*/
  	}
  }

  started_ = MODE_IN_LIBC;
}

void nshr_post_scanf(void *wrapcxt, void *user_data)
{

}