#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

struct stat st;
int f;
/*
 *madviseThread for the argv[1]
 * */
//void *madviseThread(void* arg){
//    char* str;
//    str = (char* )arg;
//    int f = open(str, O_RDONLY);
//    int i = 0, c = 0;
//    char buffer1[1024], buffer2[1024];
//    int size;
//    lseek(f, 0, SEEK_SET);              // set the file pointer begin
//    size = read(f, buffer1, sizeof(buffer1));
//    while(i < 100000000){
//        c += madvise(map, 100, MADV_DONTNEED);
//        lseek(f, 0, SEEK_SET);
//        size = read(f, buffer2, sizeof(buffer2));
//        if(size > 0 && strcmp(buffer1, buffer2)){
//            printf("Hack Success!\n\n");
//            bSuccess = 1;
//            break;
//        }
//        i++;
//    }
//    close(f);
//    printf("madvise %d\n\n", c);
//}





int main(int argc, char** argv){
    f = open(argv[1], O_RDONLY);
    fstat(f, &st);
    size_t number = 100;
//    printf("number: %zx\n", number);
//    printf("the size of size_t is %zx\n", sizeof(ssize_t));
    printf("the file size is %d\n", st.st_size);
    while(1);
    return 0;
}
