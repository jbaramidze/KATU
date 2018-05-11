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
  int a = 1;
  int b = 3;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  int c = a + b;

  if (c < 10)
  {
  	int h = A[c];
  }
  
}
