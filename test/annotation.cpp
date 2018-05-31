//#include "/custobuilds/include/stdio.h"
//#include "/custobuilds/include/stdlib.h"
//#include "/custobuilds/include/string.h" 
#include "stdio.h"
#include "stdlib.h"
#include "string.h" 
#include "dr_annotations_zhani.h"

int A[50];

int main(int argc, char **argv)
{

  volatile int a = 3;
  volatile int b = 5;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);

  if (a < 100 && b < 100)
  {
  	int c = a-b;

  	if (c < 100)
  	{
  	  volatile int v = A[c];
  	}
  }
  

}
