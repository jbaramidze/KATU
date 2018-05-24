//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";

int A[10];

int main(int argc, char **argv)
{
  char data[20];

  scanf("%s", data);

  if (strcmp(data, "qal"))
  {
  	printf(" ");
  }

  volatile int b = A[data[1]];
}
