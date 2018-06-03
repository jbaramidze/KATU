//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "limits.h" 
#include "dr_annotations_zhani.h"

typedef void (*FF)();

volatile int q = 21;

void f()
{
  q++;
}

int main(int argc, char **argv)
{
  FF fif = f;

  asm volatile (
  	"call *(%%rax)"
  	::"a"(&fif):
  		);
	/*
  volatile int qaz = 12;

  volatile xmlMallocFunc xmlMalloc;

  if (qaz == 12) xmlMalloc = malloc;

  volatile int a = 10;
  a++;

  volatile char *q = (char *) (*xmlMalloc)(a);
 
  volatile int b = q[0];
  */
}
