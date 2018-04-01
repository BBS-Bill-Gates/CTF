#include <stdio.h>
#include <stdlib.h>

int main(void)
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}

