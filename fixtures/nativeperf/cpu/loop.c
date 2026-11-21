/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop_work(int sig) { (void)sig; stopped = 1; }

__attribute__((noinline)) uint64_t soundpost_hot_loop(uint64_t value) {
    for (unsigned i = 0; i < 100000; ++i) {
        value ^= value << 7;
        value ^= value >> 9;
        value = value * UINT64_C(6364136223846793005) + i;
        __asm__ volatile("" : "+r"(value));
    }
    return value;
}
static void *worker(void *unused) {
    (void)unused;
    volatile char local_canary[] = "SOUNDPOST_CPU_LOCAL_CANARY_2026";
    volatile char *heap_canary = malloc(64);
    if (!heap_canary) return (void *)1;
    const char canary[] = "SOUNDPOST_CPU_HEAP_CANARY_2026";
    for (unsigned i = 0; i < sizeof(canary); ++i) heap_canary[i] = canary[i];
    uint64_t value = 7;
    while (!stopped) value = soundpost_hot_loop(value);
    __asm__ volatile("" : : "r"(value), "r"(local_canary), "r"(heap_canary) : "memory");
    free((void *)heap_canary);
    return 0;
}
int main(void) {
    signal(SIGINT, stop_work);
    signal(SIGTERM, stop_work);
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 2;
    /* Thread exists before ready; acquisition must include both initial TIDs. */
    if (write(STDOUT_FILENO, "ready\n", 6) != 6) return 3;
    worker(0);
    pthread_join(thread, 0);
    return 0;
}
