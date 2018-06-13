#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
 
int A[50];

int main()
{
    int filedesc = open("/home/zhani/Thesis/project/test/testcases/testfile.txt", O_WRONLY | O_APPEND | O_CREAT | O_TRUNC);
    if(filedesc < 0)
    {
    	printf("fail1.\n");
        return 1;
    }
 
    if(write(filedesc,"12\n", 3) != 3)
    {
        printf("Failed writing");    // strictly not an error, it is allowable for fewer characters than requested to be written.
        return 1;
    }

    close(filedesc);
    filedesc = open("/home/zhani/Thesis/project/test/testcases/testfile.txt", O_RDONLY);
    if(filedesc < 0)
    {
        return 1;
    	printf("fail2.\n");
    }

    char buffer[1024];
    int t = read(filedesc, buffer, 1024);

    printf("read: %d.\n", t);
    fflush(stdout);


    int q = atoi(buffer);
    volatile int vol = A[q];

 
    return 0;
}