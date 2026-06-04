#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int compute_length(const char *s) {
    int n = 0;
    while (s[n] != '\0') n++;
    return n;
}

static void copy_bytes(char *dst, const char *src, int count) {
    /* off-by-one: loop runs for indices 0..count (inclusive), writing count+1 bytes */
    for (int i = 0; i <= count; i++)
        dst[i] = src[i];
}

static int validate_input(const char *s) {
    int len = compute_length(s);
    if (len == 0) return -1;
    if (len > 512) return -2;
    return len;
}

void log_event(const char *tag, int code) {
    printf("[%s] code=%d\n", tag, code);
}

void display_result(const char *buf, int len) {
    printf("Result (%d bytes): %s\n", len, buf);
}

void process_input(const char *input) {
    char buf[64];
    int status;

    status = validate_input(input);
    if (status < 0) {
        log_event("WARN", status);
        return;
    }

    log_event("INFO", status);
    copy_bytes(buf, input, status);
    display_result(buf, status);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    process_input(argv[1]);
    return 0;
}
