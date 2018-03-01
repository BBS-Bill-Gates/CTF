#include <stdio.h>
#include <unistd.h>
#include <string.h>

int vuln(){
    char buf[80];
    setbuf(stdin, buf);
    return read(0, buf, 256);
}

int main(int argc, char** argv){
    char* welcome = "Welcome to XDCTF2015 ~!\n";
    setbuf(stdout, welcome);
    write(1, welcome, strlen(welcome));
    vuln();
    return 0;
}
