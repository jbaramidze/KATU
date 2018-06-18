/* fread example: read an entire file */
#include <stdio.h>
#include <stdlib.h>
#include "dr_annotations_zhani.h"
  

char b[8];

int main ()
{

  FILE *f = fopen("/home/zhani/Thesis/project/test/testcases/testfile.txt", "r");

  if (f == NULL)
  {
  	printf("Failed opening 1.\n");
  }

  printf("Read %d bytes.\n", fread(b, 1, 4, f));

  fclose(f);

  f = fopen("/home/zhani/Thesis/project/test/testcases/testfile2.txt", "r");

  if (f == NULL)
  {
  	printf("Failed opening 2.\n");
  }


  printf("Read %d bytes.\n", fread(b, 1, 4, f));

  fclose(f);


  return 0;
}