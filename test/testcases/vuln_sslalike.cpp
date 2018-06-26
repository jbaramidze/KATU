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

#include "dr_annotations_zhani.h"

#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)

const char *zaza = "aabc";

char A[1024*100];
char B[1024*100];


int main (int argc, char *argv[]) {

  nshrtaint((long long int) zaza, 4);

  int a = 0;

  n2s(zaza, a);

  memcpy(A, B, a);


  return 0;
}