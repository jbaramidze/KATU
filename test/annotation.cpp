#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
 
int A[50];

int main()
{
    asm volatile (
     "shld   $0x5,%%ebx,%%eax"
     :::
    	);

 
    return 0;
}