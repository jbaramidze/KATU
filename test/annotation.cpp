#include "/custobuilds/include/stdio.h"
#include "/custobuilds/include/stdlib.h"
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";

int A[10];

int main()
{
  int a = 0;
  int b = 0;
  int c = 0;
  int d = 0;
  int e = 0;
  
  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);
  nshrtaint((long long int) &c, 4);
  nshrtaint((long long int) &d, 4);
  nshrtaint((long long int) &e, 4); 
 
  if (a == 0 && b == 0 && c == 0 && d == 0 && e == 0)
  {
    a++;
  }
}
