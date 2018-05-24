#include "stdio.h"
#include "stdlib.h"
#include "dr_annotations_zhani.h"

int A[20];

int main()
{
  int a = 15;

  nshrtaint((long long int) &a, 4);

  if (a == 15)
  {
    volatile int b = A[a];
  }
}
