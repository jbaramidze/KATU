#include "/custobuilds/include/stdio.h"
#include "/custobuilds/include/stdlib.h"
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";

int main()
{
  int a = -10;
  int b = 3;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  dynamorio_annotate_zhani_signal(1);
 /////////////////////////////////////////////////////////////////
  asm volatile (
  "imul  $2, %%ebx, %%eax"
  	: : :  
   ); 
  if (10 >= a)
  {
    nshr_dump_taint((long long int) &a); 
  }
/////////////////////////////////////////////////////////////////
  dynamorio_annotate_zhani_signal(0);

/*  printf("Opened: %d.\n", a);
  printf("Read %d bytes.\n", rd);*/
}
