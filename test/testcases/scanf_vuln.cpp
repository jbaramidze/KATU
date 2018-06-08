#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

int A[10];

int main(int argc, char **argv)
{
  char data[20];

  memset(data, 0, sizeof(data));

  scanf("%s", data);

  volatile int a = atoi(data+ 4);

  volatile int b = A[a];
}
