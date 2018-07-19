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
  
  int a;

  asm volatile (
      "mov %1, %%rdi \n\t"
      "mov %2, %%esi \n\t"
      "syscall"
        : "=a" (a)
        : "r" (path1), "r" (O_RDONLY), "a" (2) // SYS_open = 2
        : "memory"
    ); 

  char buf[32];
  read(a, buf, 2);
  close(a);

  asm volatile (
      "mov %1, %%rdi \n\t"
      "mov %2, %%esi \n\t"
      "syscall"
        : "=a" (a)
        : "r" (path2), "r" (O_RDONLY), "a" (2) // SYS_open = 2
        : "memory"
    ); 

  read(a, buf+2, 2);



  return 0;
}
