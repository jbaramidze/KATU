//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "limits.h" 
#include "dr_annotations_zhani.h"
#include <ctype.h>

int A[50];

const char *xixo = "babs";

int main(int argc, char **argv)
{
  char q[6];
  q[0] = 'b';
  q[1] = 'a';
  q[2] = 'b';
  q[3] = 's';
  q[4] = 0;

  nshrtaint((long long int) &q, 6);

  //volatile int b = strcmp(q, xixo);

  volatile int qis = A[q[0]];

}
