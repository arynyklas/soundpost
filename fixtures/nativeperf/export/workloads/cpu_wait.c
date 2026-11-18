/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
/* Independently authored native export workload: one thread burns CPU and
 * naps, a second thread blocks on a condition variable with a bounded timeout
 * and burns CPU when woken. It gives the real perf CPU sampler frame-pointer
 * stacks and the scheduler tracepoints genuine blocked and runnable intervals.
 * Build: cc -O2 -g -pthread -fno-omit-frame-pointer -fno-optimize-sibling-calls \
 *           -Wl,--build-id -o cpu_wait cpu_wait.c
 * It prints "ready" once both threads exist and runs until SIGTERM/SIGINT. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static unsigned long wakes;

static void stop(int sig) { (void)sig; running = 0; }

__attribute__((noinline)) static unsigned long burn(unsigned long n) {
    volatile unsigned long v = 17;
    while (n--) v = (v ^ (v << 7)) + 19;
    return v;
}

__attribute__((noinline)) static void wait_for_wake(void) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += 60 * 1000 * 1000;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&lock);
    unsigned long seen = wakes;
    while (running && wakes == seen)
        if (pthread_cond_timedwait(&wake, &lock, &until) == ETIMEDOUT) break;
    pthread_mutex_unlock(&lock);
}

__attribute__((noinline)) static void *waiter(void *unused) {
    (void)unused;
    while (running) {
        wait_for_wake();
        burn(2000000);
    }
    return 0;
}

int main(void) {
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    pthread_t thread;
    if (pthread_create(&thread, 0, waiter, 0)) return 2;
    if (printf("ready\n") < 0 || fflush(stdout)) return 3;
    while (running) {
        burn(8000000);
        struct timespec nap = {0, 30 * 1000 * 1000};
        nanosleep(&nap, 0);
        pthread_mutex_lock(&lock);
        wakes++;
        pthread_cond_signal(&wake);
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    wakes++;
    pthread_cond_broadcast(&wake);
    pthread_mutex_unlock(&lock);
    pthread_join(thread, 0);
    return 0;
}
