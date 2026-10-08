/* Production Invoke lifecycle adapter. No test features or networking code. */
#define _POSIX_C_SOURCE 200809L
#include "vole.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char instance[21];

static int invoke(const char *request, int create) {
    char *reply = VoleInvoke(request);
    if (!reply) return 0;
    int success = strstr(reply, "\"success\":true") != NULL;
    if (success && create) {
        const char *start = strstr(reply, "\"instanceId\":\"");
        if (!start) success = 0;
        else {
            start += strlen("\"instanceId\":\"");
            size_t length = strspn(start, "0123456789");
            if (!length || length > 20 || start[length] != '"' || start[0] == '0') success = 0;
            else { memcpy(instance, start, length); instance[length] = 0; }
        }
    }
    if (!success) fprintf(stderr, "Vole public lifecycle request failed\n");
    VoleFree(reply);
    return success;
}

static int lifecycle(const char *method) {
    char request[160];
    snprintf(request, sizeof(request),
        "{\"method\":\"%s\",\"instanceId\":\"%s\",\"payload\":{}}", method, instance);
    return invoke(request, 0);
}

static char *substitute(const char *request) {
    const char *marker = strstr(request, "@INSTANCE@");
    if (!marker) return strdup(request);
    if (!instance[0] || strstr(marker + 10, "@INSTANCE@")) return NULL;
    size_t before = (size_t)(marker - request), length = strlen(instance);
    char *output = malloc(strlen(request) - 10 + length + 1);
    if (!output) return NULL;
    memcpy(output, request, before);
    memcpy(output + before, instance, length);
    strcpy(output + before + length, marker + 10);
    return output;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: interop requests.jsonl ready-file\n"); return 2; }
    sigset_t stopped;
    sigemptyset(&stopped); sigaddset(&stopped, SIGINT); sigaddset(&stopped, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &stopped, NULL)) return 2;
    signal(SIGPIPE, SIG_IGN);
    FILE *source = fopen(argv[1], "r");
    if (!source) return 2;
    char *line = NULL;
    size_t capacity = 0;
    int good = 1, count = 0;
    while (getline(&line, &capacity, source) >= 0) {
        if (++count > 3 || strlen(line) > 1024 * 1024) { good = 0; break; }
        char *request = substitute(line);
        if (!request || !invoke(request, count == 2)) good = 0;
        free(request);
        if (!good) break;
    }
    if (ferror(source) || count != 3) good = 0;
    free(line); fclose(source);
    if (good) {
        FILE *ready = fopen(argv[2], "w");
        if (!ready || fclose(ready)) good = 0;
        else {
            int received;
            if (sigwait(&stopped, &received)) good = 0;
        }
    }
    if (instance[0]) {
        if (!lifecycle("stop")) good = 0;
        if (!lifecycle("destroyInstance")) good = 0;
    }
    return good ? 0 : 1;
}
