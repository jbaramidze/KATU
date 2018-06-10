#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  int a = atoi(argv[1]);

  volatile int b = A[a];
}
