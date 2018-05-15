#include "/custobuilds/include/stdio.h"
#include "/custobuilds/include/stdlib.h"
#include "dr_annotations_zhani.h"

const char *path = "/home/zhani/Thesis/test/zaza";


void sum(int a, int b) {}
void subtract(int a, int b) {}
void mul(int a, int b) {}
void ddiv(int a, int b) {}

void (*p[4]) (int x, int y);

int main()
{
asm volatile ( "cbw \t\n cwde \t\n cdqe \t\n" ::: );
asm volatile ( "cwd \t\n cdq \t\n cqo \t\n" ::: );
  
/*  int a = 1;
  int b = 3;
  int c = 3;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &b, 4);
  nshrtaint((long long int) &c, 4);

  p[0] = sum; 
  p[1] = subtract; 
  p[2] = mul; 
  p[3] = ddiv;

  (*p[a]) (2, 3);
  */
  
}
