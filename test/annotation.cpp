#include <stdio.h>
#include <string.h>

#define SIZE 1
#define NUMELEM 5

int A[100];

int main(void)
{
    unsigned long long a;
    scanf("%llu", &a);

    printf("%d.\n", __builtin_clzll(a));

    return 0;
}