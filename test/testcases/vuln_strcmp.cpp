#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  char data[20];

  data[0] = 'a';
  data[1] = 'b';
  data[2] = 'c';
  data[3] = 'd';
  data[4] = '\0';

  nshrtaint((long long int) &data, 20);


  int q = strcmp(data, "abed");
  volatile int b = A[data[q+1]];
}
