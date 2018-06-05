#include <stdio.h>
#include <string.h>

#define SIZE 1
#define NUMELEM 5

int A[100];

int main(void)
{
    FILE* fd = NULL;
    char buff[100];
    memset(buff,0,sizeof(buff));

    fd = fopen("/home/zhani/Thesis/project/test/build/test.txt","rw+");

    if(NULL == fd)
    {
        printf("\n fopen() Error!!!\n");
        return 1;
    }

    if(SIZE*NUMELEM != fread(buff,SIZE,NUMELEM,fd))
    {
        printf("\n fread() failed\n");
        return 1;
    }

    printf("The bytes read are [%s]\n",buff);

    fclose(fd);
/*
    if(0 != fseek(fd,11,SEEK_CUR))
    {
        printf("\n fseek() failed\n");
        return 1;
    }

    printf("\n fseek() successful\n");

    if(SIZE*NUMELEM != fwrite(buff,SIZE,strlen(buff),fd))
    {
        printf("\n fwrite() failed\n");
        return 1;
    }

    printf("\n fwrite() successful, data written to text file\n");


    printf("\n File stream closed through fclose()\n");
    */

    return 0;
}