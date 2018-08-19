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

 
int main () {

  int b = 10;

  asm volatile ( "mov (%%rax), %%rax" ::"a"(&b): );

  return 0;
}
