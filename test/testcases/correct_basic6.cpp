#include <stdio.h>
#include <stdlib.h>
#include "dr_annotations_zhani.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *path1 = "/home/zhani/Thesis/test/zaza";
const char *path2 = "/home/zhani/Thesis/test/zaza1";

int A[10];
 
int main () {

  int a = 2;
  int b = 2;

  nshrtaint((long long int) &a, 4);
  nshrtaint((long long int) &a, b);

  volatile int c = a + b;
  
  if (c < 100 && a > 0 && b > 0)
  {
    volatile int d = A[b];
  } 

  return 0;
}
