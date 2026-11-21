// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static void stop(int sig) { (void)sig; running = 0; }
static void nap(long ns) { struct timespec t = {0, ns}; nanosleep(&t, NULL); }
__attribute__((noinline)) static void soundpost_futex_wait(_Atomic int *word) {
 int value = atomic_load(word);
 struct timespec timeout = {0, 20000000};
 syscall(SYS_futex, word, FUTEX_WAIT, value, &timeout, NULL, 0);
}
int main(void) {
 signal(SIGTERM, stop); signal(SIGINT, stop);
 _Atomic int *word = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
 if (word == MAP_FAILED) return 2;
 atomic_init(word, 0);
 pid_t foreign = fork();
 if (foreign < 0) return 3;
 if (foreign == 0) {
  prctl(PR_SET_NAME, "SECRET_WAKER", 0, 0, 0);
  while (running && getppid() != 1) { nap(5000000); atomic_fetch_add(word, 1); syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0); }
  _exit(0);
 }
 prctl(PR_SET_NAME, "SECRET_SLEEPER", 0, 0, 0);
 printf("ready %d\n", foreign); fflush(stdout);
 while (running) { soundpost_futex_wait(word); nap(3000000); }
 kill(foreign, SIGTERM); waitpid(foreign, NULL, 0); munmap(word, 4096); return 0;
}
