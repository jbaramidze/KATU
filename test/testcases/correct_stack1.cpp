#include "stdio.h"
#include "stdlib.h"
#include "dr_annotations_zhani.h"

int A[20];

int main()
{
  int a = 15;
  int b = 3;

  nshrtaint((long long int) &a, 4);
 
  asm volatile (	
   	"pushq $10 \n \t"
   	"push $10 \n \t"
   	"push %%rax \n \t"
   	"push $10 \n \t"
   	"pop %%rcx \n \t"
   	"pop %%rbx \n \t"
   	"pop %%rcx \n \t"
   	"popq %%rcx \n \t"
   	:"=b"(b) : "a"(a) : "rcx" 
   	);

  if (a > 10 && a < 30)
  {
    volatile int h = A[b];
  }
}
