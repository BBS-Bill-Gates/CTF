#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int test(){
    char *dest01 = (char*) malloc(0x40);
    char *dest02 = (char*) malloc(0x40);
    fgets(dest01, 0x100, stdin);
    *dest01 = (int)dest02 & 0xff;
    *(dest01+1) = ((int)dest02 & 0xff00) >> 8;
    *(dest01+2) = ((int)dest02 & 0xff0000) >> 16;
    *(dest01+3) = ((int)dest02 & 0xff000000) >> 24;
    *(dest01+4) = '\x00';
    *(dest01+5) = '\x00'; 
    *(dest01+6) = '\x00'; 
    *(dest01+7) = '\x00';  
    free(dest01);
    return 0;
}
void print(char* s){
    printf("the string is %s\n", s);
}

int main(void){
    char* s = "hello, world";
    puts("start\n");
    print(s);
    print(s);
    print(s);
    print(s);
    test();
    puts("over\n");
    return 0;
}
