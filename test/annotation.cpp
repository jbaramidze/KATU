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

long long a = 10;

asm volatile (
      "mov $32141000000000, %%rax \n \t"
      "mov $2, %%eax"
       : "=a" (a) ::
);

  printf("%lld\n", a);
  return 0;
}
