#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  char data[200];

  data[0] = '1';
  data[1] = '2';
  data[2] = '3';
  data[3] = '\0';

  nshrtaint((long long int) &data, 20);

  volatile int t = strcmp(data, "123");

  int a = atoi(data);
  volatile int b = A[a];
}
