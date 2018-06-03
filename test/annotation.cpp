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
  volatile int a;
  scanf("%d", &a);


  volatile int *b = (int *)malloc(3);

  *b = 17;
}
