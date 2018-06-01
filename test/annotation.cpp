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
  volatile int a = 30;

  nshrtaint((long long int) &a, 4);

  a/=1;
  a/=2;
  a/=3;
  a/=4;
  a/=5;
  a/=6;
  a/=7;
  a/=8;
  a/=9;
  a/=10;
  a/=11;
  a/=12;
  a/=13;
  a/=14;
  a/=15;

  volatile int b = A[a];


}
