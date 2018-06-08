#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "limits.h" 
#include "dr_annotations_zhani.h"
#include <ctype.h>

int A[50];

const char *xixo = "123";

int main(int argc, char **argv)
{
  char q[6];
  q[0] = '1';
  q[1] = '2';
  q[2] = '3';
  q[3] = 0;

  nshrtaint((long long int) &q, 6);

  volatile int b = strcmp(q, xixo);

  int a = atoi(q);

  volatile int qis = A[a];

}
