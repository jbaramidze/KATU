/* fread example: read an entire file */
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



#include "dr_annotations_zhani.h"

const char *path1 = "/home/zhani/Thesis/test/zaza";
const char *path2 = "/home/zhani/Thesis/test/zaza1";

int main () {
  int a = 100;
  nshrtaint((long long int) &a, 4);
  a = a & 0x00FF0000;

  char *q = (char *) &a;
  nshr_dump_taint((long long int) &q[0]);
  nshr_dump_taint((long long int) &q[1]);
  nshr_dump_taint((long long int) &q[2]);
  nshr_dump_taint((long long int) &q[3]);
  return 0;
}
