#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_info(const char *name, int id) {
    printf("[INFO] User: %s, ID: %d\n", name, id);
}

void greet(const char *username) {
    char msg[64];
    snprintf(msg, sizeof(msg), "Hello, %s! Welcome to the system.", username);
    printf("%s\n", msg);
}

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("Processed: %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    print_info("guest", 1001);
    greet(argv[1]);
    vuln(argv[1]);

    return 0;
}
