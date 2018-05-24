#include "stdio.h"
#include "stdlib.h"
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";


void (*p[4]) (int x, int y);

int main()
{

  int a = 1;
  int b = 3;
  int c = 3;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);
  nshrtaint((long long int) &c, 4);

  (*p[a]) (2, 3);
  
}
