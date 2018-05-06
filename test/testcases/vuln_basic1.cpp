#include "/custobuilds/include/stdio.h"
#include "/custobuilds/include/stdlib.h"
#include "dr_annotations_zhani.h"

int A[20];

int main()
{
  int a = 15;

  nshrtaint((long long int) &a, 4);

  dynamorio_annotate_zhani_signal(1);
/////////////////////////////////////////////////////////////////

  int b = A[a];

/////////////////////////////////////////////////////////////////
  dynamorio_annotate_zhani_signal(0);
}
