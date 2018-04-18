#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void){
    char* s0 = malloc(0x200);
    char* s1 = malloc(0x18);
    char* s2 = malloc(0xf0);
    char* s3 = malloc(0x20);
    printf("begin\n");
    printf("%p\n", s0);
    printf("input s0\n");
    read(0, s0, 0x200);
    printf("input s1\n");
    read(0, s1, 0x19);
    free(s2);
    return 0;
}
