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


  nshrtaint((long long int) &data, 100);

  memset(data, 2, 20);

  volatile int q = A[data[3]];
}
