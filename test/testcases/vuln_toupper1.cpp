#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dr_annotations_zhani.h"
#include <ctype.h>

int A[10];

int main(int argc, char **argv)
{
  volatile int a = 6;
  nshrtaint((long long int) &a, 4);
  volatile int b = toupper(a);
  volatile int c = tolower(b);

  volatile int d = A[c];
}
