/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
/*
 * Soundpost 04.08 privacy canary workload.
 *
 * Places eight distinct public synthetic sentinels where a careless native
 * collector could leak them: thread name (comm), stack locals, heap, environment,
 * command line, file paths and input/DB-like strings. The sentinels are derived
 * from a per-run nonce that only the fixture verifier chooses and passes in:
 *
 *   canary SPCNRY-ARGV-<nonce> [seconds]
 *   environment SPCNRY_ENV=SPCNRY-ENV-<nonce>
 *   stdin   "INPUT <text containing SPCNRY-INPUT-<nonce>>\n"
 *           "DB <text containing SPCNRY-DB-<nonce>>\n"
 *   executable path contains a directory SPCNRY-PATH-<nonce>
 *
 * It verifies every placement against its own memory/proc state and prints one
 * line "ready <kind>,<kind>,..." (kinds only, never values). The workload then
 * runs a frame-pointer-friendly call chain with real CPU work on one thread,
 * renames its threads repeatedly (so the kernel ring carries PERF_RECORD_COMM
 * records holding the comm sentinel) and blocks/wakes on a condition variable so
 * scheduler tracepoints would have genuine off-CPU evidence on a host that
 * permits them.
 *
 * Build: cc -O2 -pthread -fno-omit-frame-pointer -g -o canary canary.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#define NONCE_LEN 6
#define SECRET_MAX 160

static volatile sig_atomic_t stopped;
static void stop_work(int sig) { (void)sig; stopped = 1; }

struct secrets {
    char comm[16];
    char stack_value[64];
    char heap_value[64];
    char env_value[64];
    char argv_value[64];
    char path_marker[64];
    char input_line[SECRET_MAX];
    char db_line[SECRET_MAX];
    char *heap_copy;   /* heap placement */
    char *input_heap;  /* input string also kept on the heap */
    char *db_heap;     /* DB-like string kept on the heap */
};
static struct secrets S;
static pthread_mutex_t wake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake_cond = PTHREAD_COND_INITIALIZER;
static unsigned long wake_count;

#define NOINLINE __attribute__((noinline, optimize("no-optimize-sibling-calls", "no-omit-frame-pointer")))

NOINLINE uint64_t spcnry_hot(uint64_t value) {
    for (unsigned i = 0; i < 100000; ++i) {
        value ^= value << 7;
        value ^= value >> 9;
        value = value * UINT64_C(6364136223846793005) + i;
        __asm__ volatile("" : "+r"(value));
    }
    return value ^ 1;
}
NOINLINE uint64_t spcnry_hash_text(const char *text, uint64_t value) {
    for (size_t i = 0; text[i]; ++i) value = (value ^ (unsigned char)text[i]) * UINT64_C(1099511628211);
    value = spcnry_hot(value);
    return value + 3;
}
NOINLINE uint64_t spcnry_handle_request(uint64_t value) {
    /* Stack local placement: the sentinel lives in this frame while the CPU is hot. */
    volatile char stack_secret[64];
    memcpy((void *)stack_secret, S.stack_value, sizeof(S.stack_value));
    value = spcnry_hash_text((const char *)stack_secret, value);
    value = spcnry_hash_text(S.heap_copy, value);
    value = spcnry_hash_text(S.input_heap, value);
    value = spcnry_hash_text(S.db_heap, value);
    __asm__ volatile("" : : "r"(stack_secret) : "memory");
    return value + 5;
}
static void rename_thread(void) { prctl(PR_SET_NAME, (unsigned long)S.comm, 0, 0, 0); }
static void *worker(void *unused) {
    (void)unused;
    uint64_t value = 7;
    unsigned round = 0;
    while (!stopped) {
        if (round++ % 4 == 0) rename_thread();
        value = spcnry_handle_request(value);
    }
    __asm__ volatile("" : : "r"(value));
    return 0;
}
static void *blocker(void *unused) {
    (void)unused;
    rename_thread();
    pthread_mutex_lock(&wake_lock);
    unsigned long seen = 0;
    while (!stopped) {
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 20 * 1000 * 1000;
        if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
        while (wake_count == seen && !stopped) {
            if (pthread_cond_timedwait(&wake_cond, &wake_lock, &until) == ETIMEDOUT) break;
        }
        seen = wake_count;
        rename_thread();
    }
    pthread_mutex_unlock(&wake_lock);
    return 0;
}

static int fail(const char *what, const char *kind) {
    fprintf(stderr, "%s %s\n", what, kind);
    return 3;
}
static int has_hex_nonce(const char *s) {
    for (int i = 0; i < NONCE_LEN; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return s[NONCE_LEN] == 0;
}
static int read_line(char *out, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r != 1) return -1;
        if (c == '\n') break;
        out[n++] = c;
    }
    out[n] = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *argv_prefix = "SPCNRY-ARGV-";
    if (strncmp(argv[1], argv_prefix, strlen(argv_prefix)) != 0) return 2;
    const char *nonce = argv[1] + strlen(argv_prefix);
    if (!has_hex_nonce(nonce)) return 2;
    long seconds = argc > 2 ? strtol(argv[2], 0, 10) : 0;

    snprintf(S.comm, sizeof S.comm, "SPCNRY-C-%s", nonce);
    snprintf(S.stack_value, sizeof S.stack_value, "SPCNRY-STACK-%s", nonce);
    snprintf(S.heap_value, sizeof S.heap_value, "SPCNRY-HEAP-%s", nonce);
    snprintf(S.env_value, sizeof S.env_value, "SPCNRY-ENV-%s", nonce);
    snprintf(S.argv_value, sizeof S.argv_value, "SPCNRY-ARGV-%s", nonce);
    snprintf(S.path_marker, sizeof S.path_marker, "SPCNRY-PATH-%s", nonce);
    char input_marker[64], db_marker[64];
    snprintf(input_marker, sizeof input_marker, "SPCNRY-INPUT-%s", nonce);
    snprintf(db_marker, sizeof db_marker, "SPCNRY-DB-%s", nonce);

    /* argv */
    if (strcmp(argv[1], S.argv_value) != 0) return fail("placement_failed", "argv");
    /* environment */
    const char *env = getenv("SPCNRY_ENV");
    if (!env || strcmp(env, S.env_value) != 0) return fail("placement_failed", "env");
    /* stdin: input and DB-like strings */
    if (read_line(S.input_line, sizeof S.input_line) || strncmp(S.input_line, "INPUT ", 6) != 0 || !strstr(S.input_line, input_marker))
        return fail("placement_failed", "input");
    if (read_line(S.db_line, sizeof S.db_line) || strncmp(S.db_line, "DB ", 3) != 0 || !strstr(S.db_line, db_marker))
        return fail("placement_failed", "db");
    /* heap */
    S.heap_copy = strdup(S.heap_value);
    S.input_heap = strdup(S.input_line);
    S.db_heap = strdup(S.db_line);
    if (!S.heap_copy || !S.input_heap || !S.db_heap || strcmp(S.heap_copy, S.heap_value) != 0) return fail("placement_failed", "heap");
    /* file path: the executable lives below a SPCNRY-PATH directory and a data file with the marker is held open */
    char exe[4096];
    ssize_t exe_len = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (exe_len <= 0) return fail("placement_failed", "path");
    exe[exe_len] = 0;
    if (!strstr(exe, S.path_marker)) return fail("placement_failed", "path");
    const char *tmp = getenv("TMPDIR");
    char data_path[4096];
    snprintf(data_path, sizeof data_path, "%s/%s.dat", tmp && *tmp ? tmp : "/tmp", S.path_marker);
    int data_fd = open(data_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (data_fd < 0) return fail("placement_failed", "path");
    unlink(data_path);
    char link[64], fd_target[4096];
    snprintf(link, sizeof link, "/proc/self/fd/%d", data_fd);
    ssize_t fd_len = readlink(link, fd_target, sizeof fd_target - 1);
    if (fd_len <= 0) return fail("placement_failed", "path");
    fd_target[fd_len] = 0;
    if (!strstr(fd_target, S.path_marker)) return fail("placement_failed", "path");
    /* comm */
    char got_comm[16] = {0};
    if (prctl(PR_SET_NAME, (unsigned long)S.comm, 0, 0, 0) || prctl(PR_GET_NAME, (unsigned long)got_comm, 0, 0, 0) || strcmp(got_comm, S.comm) != 0)
        return fail("placement_failed", "comm");
    /* stack: confirmed inside the hot frame; confirm the buffer content once here too */
    volatile char stack_probe[64];
    memcpy((void *)stack_probe, S.stack_value, sizeof(S.stack_value));
    if (strcmp((const char *)stack_probe, S.stack_value) != 0) return fail("placement_failed", "stack");

    signal(SIGINT, stop_work);
    signal(SIGTERM, stop_work);
    pthread_t cpu_thread, wait_thread;
    if (pthread_create(&cpu_thread, 0, worker, 0)) return 2;
    if (pthread_create(&wait_thread, 0, blocker, 0)) return 2;
    /* Both worker threads exist before "ready"; acquisition must include all initial TIDs. */
    if (printf("ready comm,stack,heap,env,argv,path,input,db\n") < 0 || fflush(stdout)) return 3;

    time_t deadline = seconds > 0 ? time(0) + seconds : 0;
    while (!stopped && (!deadline || time(0) < deadline)) {
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, 0);
        pthread_mutex_lock(&wake_lock);
        wake_count++;
        pthread_cond_signal(&wake_cond);
        pthread_mutex_unlock(&wake_lock);
        rename_thread();
    }
    stopped = 1;
    pthread_cond_signal(&wake_cond);
    pthread_join(cpu_thread, 0);
    pthread_join(wait_thread, 0);
    close(data_fd);
    free(S.heap_copy);
    free(S.input_heap);
    free(S.db_heap);
    __asm__ volatile("" : : "r"(stack_probe) : "memory");
    return 0;
}
