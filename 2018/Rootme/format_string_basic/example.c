#include <stdio.h>
#include <string.h>

int main(int argc, char** argv){
    int a = 1024;
    char buf[1024];
    strcpy(buf, argv[1]);
    printf(buf);
    printf("\n");
    return 0;
}
