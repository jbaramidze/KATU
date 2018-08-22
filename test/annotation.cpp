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


#define haszero(v) (((v) - 0x01010101UL) & ~(v) & 0x80808080UL)
 
int main () {


  int a = 256*256*256*8 + 256*256*0 + 256*99 + 8;

  printf("%d.\n", haszero(a));

  return 0;
}
