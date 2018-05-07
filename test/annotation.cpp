#include "/custobuilds/include/stdio.h"
#include "/custobuilds/include/stdlib.h"
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";

extern "C"
{
  void func()
  {
    
  }
}

int A[20];

int main()
{
  int a = 15;
  int b = 3;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  //dynamorio_annotate_zhani_signal(1);
 /////////////////////////////////////////////////////////////////
/*
   asm volatile (
   	//"cmp $10, %%eax \n \t"
   	"cmp $10, %%eax \n \t"
   	"ja func"
   	: : "a"(a) : );
*/

  if (a > 10 && a < 30)
  {
  	int b = A[a];
  	b = b + 9;
    nshr_dump_taint((long long int) &a); 
  }
  

/////////////////////////////////////////////////////////////////
  //dynamorio_annotate_zhani_signal(0);

/*  printf("Opened: %d.\n", a);
  printf("Read %d bytes.\n", rd);*/
}
