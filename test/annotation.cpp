/* fread example: read an entire file */
#include <stdio.h>
#include <stdlib.h>

int main () {
  FILE * pFile;

  pFile = fopen ( "/dev/random" , "r" );
  fclose(pFile);
  pFile = fopen ( "/dev/random" , "r" );

  char buff[1024];
  fgets(buff, 10, pFile);

  printf("Read: %s", buff);

  fclose(pFile);
  return 0;
}