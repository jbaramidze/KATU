#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  char data[20];

  scanf("%s", data);

  volatile int b = A[data[6]];
}
