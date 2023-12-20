#include <stdio.h>

__attribute__ ((constructor)) void msg(int argc, char **argv) {
  printf("Hello from msg() constructor\n");
}

__attribute__ ((constructor)) void seccond(int argc, char **argv) {
  printf("Hello from seccond() constructor\n");
}

void not_called() {
  puts("[-] This shoud not be called[-]");
}

int main() {
  puts("[*] Hello from main [*]");
}