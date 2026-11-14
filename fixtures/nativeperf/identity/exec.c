/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) static void *soundpost_exec_spin(void *unused) {
    (void)unused;
    volatile uint64_t value = 1;
    for (;;) value = value * 6364136223846793005ULL + 1;
    return NULL;
}
int main(int argc, char **argv) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, soundpost_exec_spin, NULL) != 0) return 2;
    puts("ready"); fflush(stdout);
    if (argc == 2 && strcmp(argv[1], "after") == 0) { (void)soundpost_exec_spin(NULL); return 3; }
    if (getchar() != 'e') return 4;
    /* Same executable inode/build ID/starttime: only real COMM_EXEC proves the
       generation boundary. Do not replace this with a different-file exec. */
    execl(argv[0], argv[0], "after", (char *)NULL);
    return 5;
}
