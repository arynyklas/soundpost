/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
/* Single-threaded namespace-case workload: spins ~30 ms, then blocks ~3 ms in poll() on stdin, forever. The poll is
   the scheduler off-CPU interval and the command channel. Commands (one per line) answer with "ack <name>":
     exec          execl(argv[0]) of the same path (same file: only COMM_EXEC shows it)
     setns <path>  setns() into the mount namespace named by <path> (a namespace file)
     unshare-mnt   unshare(CLONE_NEWNS)
     exit          exit(0)
   -DVARIANT=n changes the code (and so the GNU build ID), never the behaviour. One thread only: a second one would end
   the capture by itself (thread coverage). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef VARIANT
#define VARIANT 1
#endif

__attribute__((noinline)) static uint64_t soundpost_ns_leaf(uint64_t value) {
    for (unsigned i = 0; i < 100000; ++i) value = value * 6364136223846793005ULL + 1442695040888963407ULL + VARIANT;
    __asm__ volatile("" : "+r"(value));
    return value;
}
__attribute__((noinline)) static uint64_t soundpost_ns_parent(uint64_t value) {
    uint64_t result = soundpost_ns_leaf(value);
    __asm__ volatile("" : "+r"(result));
    return result;
}
static void ack(const char *name) { printf("ack %s\n", name); fflush(stdout); }
static int command(char *argv0, char *line) {
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
    if (strcmp(line, "exit") == 0) { ack("exit"); exit(0); }
    if (strcmp(line, "unshare-mnt") == 0) { ack(unshare(CLONE_NEWNS) == 0 ? "unshare-mnt" : "unshare-mnt-failed"); return 1; }
    if (strncmp(line, "setns ", 6) == 0) {
        int fd = open(line + 6, O_RDONLY | O_CLOEXEC);
        ack(fd >= 0 && setns(fd, CLONE_NEWNS) == 0 ? "setns" : "setns-failed");
        if (fd >= 0) close(fd);
        return 1;
    }
    if (strcmp(line, "exec") == 0) {
        execl(argv0, argv0, "after", (char *)NULL);
        ack("exec-failed");
        return 1;
    }
    return 0;
}
int main(int argc, char **argv) {
    int idle = argc > 1 && strcmp(argv[1], "idle") == 0;
    puts(argc > 1 && strcmp(argv[1], "after") == 0 ? "ready after" : "ready"); fflush(stdout);
    uint64_t value = 1;
    char line[512];
    size_t used = 0;
    for (;;) {
        if (!idle) value = soundpost_ns_parent(value);
        struct pollfd p = {0, POLLIN, 0};
        if (poll(&p, 1, idle ? -1 : 3) > 0 && (p.revents & POLLIN)) {
            ssize_t got = read(0, line + used, sizeof line - used - 1);
            if (got <= 0) return value == 0 ? 4 : 0;
            used += (size_t)got;
            line[used] = 0;
            char *nl;
            while ((nl = strchr(line, '\n')) != NULL) {
                *nl = 0;
                command(argv[0], line);
                size_t rest = used - (size_t)(nl + 1 - line);
                memmove(line, nl + 1, rest);
                used = rest;
                line[used] = 0;
            }
        }
    }
}
