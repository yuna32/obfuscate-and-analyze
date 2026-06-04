// target.c  — test target for the ELF obfuscator
#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("Hello, %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <name>\n", argv[0]);
        return 1;
    }
    vuln(argv[1]);
    return 0;
}
