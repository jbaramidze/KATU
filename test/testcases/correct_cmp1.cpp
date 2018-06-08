#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  int a = 9;
  int b = 3;
  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  if (a > b)
  {
  	 if (b > 0 && a < 100)
  	 {
  	 	volatile int c = A[b];
  	 }
  }
}
