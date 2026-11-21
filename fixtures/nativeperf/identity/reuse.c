/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static void stop(int sig) { (void)sig; running = 0; }
__attribute__((noinline)) static uint64_t soundpost_identity_leaf(uint64_t value) {
    for (unsigned i = 0; i < 100000; ++i) value = value * 6364136223846793005ULL + 1;
    __asm__ volatile("" : "+r"(value));
    return value;
}
__attribute__((noinline)) static uint64_t soundpost_identity_parent(uint64_t value) {
    uint64_t result = soundpost_identity_leaf(value);
    __asm__ volatile("" : "+r"(result));
    return result;
}
static void *brief_thread(void *unused) { (void)unused; (void)soundpost_identity_parent(1); return NULL; }
int main(int argc, char **argv) {
    signal(SIGTERM, stop); signal(SIGINT, stop);
    if (argc == 2 && strcmp(argv[1], "exit") == 0) return 0;
    if (argc == 2 && strcmp(argv[1], "threads") == 0) {
        for (unsigned i = 0; i < 2000; ++i) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, brief_thread, NULL) != 0) return 2;
            if (pthread_join(thread, NULL) != 0) return 3;
        }
        return 0;
    }
    puts("ready"); fflush(stdout);
    uint64_t value = 1;
    while (running) value = soundpost_identity_parent(value);
    return value == 0 ? 4 : 0;
}
