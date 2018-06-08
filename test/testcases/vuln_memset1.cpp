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
 
  char data[1000];

  int t;
  nshrtaint((long long int) &t, 4);

  memset(data, t, 200);

  int d = atoi(data);

  volatile int q = A[d];
}

