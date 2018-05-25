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
  volatile int a = 3;

  nshrtaint((long long int) &a, 4);

  a = a + a;
  a = a*a;
  a = a + 5;
  a = a - 4;
  a++;
  a--;
  volatile int b = a;
    

  volatile int q = A[b];
}
