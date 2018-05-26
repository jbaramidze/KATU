//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

int A[50];

int main(int argc, char **argv)
{
  volatile int a = 0;

  nshrtaint((long long int) &a, 4);


  asm volatile (
  	"neg %%eax"
  	: "=a"(a) : "a"(a) :
  	);

  printf("%d.\n", a);
/*

  if (a < 100)
  {
  	a = a*-1;
  	if (a < 100)
  	{
  	  a = a*-11;
  	  printf("a.\n\n\n");
  	  volatile int b = A[a];
  	}
  }
  */
}
