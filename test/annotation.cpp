//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "limits.h" 
#include "dr_annotations_zhani.h"

int A[50];

int main(int argc, char **argv)
{

  asm volatile (
  	"imul $12, %%cx"
  	:::);
  	
/*
  volatile int a = 10;
  volatile int b = 2;
    
  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  volatile int c = a/b;
 
  nshr_dump_taint((long long int) &c);*/
}
