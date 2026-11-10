//go:build ignore

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Native profiling acceptance workloads (task 04.09). Build:
//   cc -O2 -pthread -fno-omit-frame-pointer -g -o fixtures/nativeperf/acceptance/workloads fixtures/nativeperf/acceptance/workloads.c
// Usage: workloads <mode> <ground-truth-file> <seconds> <nonce>
// Modes: cpu | nofp | fanout (16 hot threads) | blocking | contend | migrate | exec
//
// The program creates every thread (and, for the blocking mode, the one foreign
// waker process) BEFORE it prints "ready <pid>": a capture armed afterwards sees
// the complete thread set, because the native helper treats a thread or process
// creation or exit inside a live capture as a coverage change. It then blocks on
// stdin until the verifier writes "go\n". Every blocking interval, CPU phase and
// runnable delay is recorded as one JSON line in the ground-truth file using
// CLOCK_MONOTONIC nanoseconds taken by this program itself (never inferred from
// a profiler). The final "summary" line says whether the program verified its
// own ground truth; the exit status is 0 only when it did. After the summary it
// prints "done" and idles (threads parked) until the verifier writes "exit\n",
// so the target never exits underneath a live scheduler session.
// The nonce becomes the thread names, an environment value and a stack local:
// the verifier searches the acquisition socket for it (privacy canary).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static FILE *gt;
static pthread_mutex_t gt_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_int failures;
static char nonce[64];
static const char *mode_name;

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static uint64_t thread_cpu_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static int tid(void) { return (int)syscall(SYS_gettid); }

static void emit(const char *kind, uint64_t start, uint64_t end, uint64_t expect_min, uint64_t extra) {
	pthread_mutex_lock(&gt_lock);
	fprintf(gt, "{\"mode\":\"%s\",\"kind\":\"%s\",\"pid\":%d,\"tid\":%d,\"start_ns\":%llu,\"end_ns\":%llu,\"expected_min_ns\":%llu,\"extra\":%llu}\n", mode_name, kind, (int)getpid(), tid(), (unsigned long long)start, (unsigned long long)end, (unsigned long long)expect_min, (unsigned long long)extra);
	fflush(gt);
	pthread_mutex_unlock(&gt_lock);
}
static void fail(void) { atomic_fetch_add(&failures, 1); }

static void name_thread(const char *role) {
	char name[16];
	snprintf(name, sizeof name, "%.4s%.10s", role, nonce);
	prctl(PR_SET_NAME, name, 0, 0, 0);
}

/* GCC omits the frame pointer of leaf functions even under -fno-omit-frame-pointer,
   which would hide the hot function's caller from a frame-pointer callchain. A
   dynamic stack allocation forces a real frame (rbp) in the hot functions. */
static uint64_t sink;
static volatile int frame_size = 1;
#define FORCE_FRAME() do { char *pad_ = __builtin_alloca(frame_size); __asm__ volatile("" ::"r"(pad_) : "memory"); } while (0)

/* ---- CPU hot loop with frame pointers (the baseline callchain) ---- */
__attribute__((noipa)) uint64_t spqual_hot(uint64_t x) {
	FORCE_FRAME();
	for (int i = 0; i < 8192; i++) {
		x = x * 6364136223846793005ull + 1442695040888963407ull;
		x ^= x >> 29;
	}
	return x;
}
__attribute__((noipa)) uint64_t spqual_hash_block(uint64_t x) {
	x = spqual_hot(x);
	return x ^ (x >> 7);
}
__attribute__((noipa)) uint64_t spqual_serve(uint64_t x) {
	x = spqual_hash_block(x);
	return x + 1;
}
/* the same hot function again, reached after exec so generations are distinguishable */
__attribute__((noipa)) uint64_t spqual_hot_after_exec(uint64_t x) {
	FORCE_FRAME();
	for (int i = 0; i < 8192; i++) {
		x = x * 2862933555777941757ull + 3037000493ull;
		x ^= x >> 31;
	}
	return x;
}
__attribute__((noipa)) uint64_t spqual_serve_after_exec(uint64_t x) {
	x = spqual_hot_after_exec(x);
	return x + 3;
}

/* ---- the same chain compiled WITHOUT frame pointers ---- */
#define NOFP __attribute__((noipa, optimize("omit-frame-pointer")))
NOFP uint64_t spqual_nofp_hot(uint64_t x) {
	for (int i = 0; i < 8192; i++) {
		x = x * 6364136223846793005ull + 1442695040888963407ull;
		x ^= x >> 29;
	}
	return x;
}
NOFP uint64_t spqual_nofp_mid(uint64_t x) {
	x = spqual_nofp_hot(x);
	return x ^ (x >> 7);
}
NOFP uint64_t spqual_nofp_serve(uint64_t x) {
	x = spqual_nofp_mid(x);
	return x + 1;
}
__attribute__((noipa)) uint64_t spqual_nofp_entry(uint64_t x) {
	x = spqual_nofp_serve(x);
	return x + 2;
}

static atomic_int go_flag;
static atomic_int finished_workers, exit_flag;
static int expect_hot = 1; /* 0 while threads deliberately contend for one CPU */
static int pinned_contention; /* the contend mode only */

__attribute__((noipa)) void spqual_worker_loop(uint64_t seconds_ns, int variant) {
	uint64_t start = now_ns(), cpu0 = thread_cpu_ns(), x = 0x9e3779b97f4a7c15ull;
	uint64_t deadline = start + seconds_ns, iterations = 0;
	while (now_ns() < deadline) {
		iterations++;
		for (int i = 0; i < 64; i++) {
			if (variant == 0) x = spqual_serve(x);
			else if (variant == 1) x = spqual_nofp_entry(x);
			else x = spqual_serve_after_exec(x);
		}
	}
	sink ^= x;
	uint64_t end = now_ns(), cpu = thread_cpu_ns() - cpu0;
	emit("iterations", start, end, 0, iterations);
	emit(variant == 1 ? "cpu_phase_nofp" : variant == 2 ? "cpu_phase_after_exec" : "cpu_phase", start, end, 0, cpu);
	/* a hot loop that ran for under 80 percent of its wall time on CPU did not run hot */
	if (expect_hot && cpu * 10 < (end - start) * 8) fail();
}

struct worker { int variant; uint64_t ns; int cpu; uint64_t wall, cpu_ns; };
static void *thread_main(void *arg) {
	struct worker *w = arg;
	name_thread("work");
	if (w->cpu >= 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(w->cpu, &set);
		if (sched_setaffinity(0, sizeof set, &set) != 0) fail();
	}
	while (!atomic_load(&go_flag)) usleep(1000);
	uint64_t s = now_ns(), c0 = thread_cpu_ns();
	spqual_worker_loop(w->ns, w->variant);
	w->wall = now_ns() - s;
	w->cpu_ns = thread_cpu_ns() - c0;
	/* Park instead of exiting: a thread exit inside a live capture changes the
	   target thread set, which the helper (correctly) treats as a coverage change
	   and ends the session before its final proof. */
	atomic_fetch_add(&finished_workers, 1);
	while (!atomic_load(&exit_flag)) usleep(1000);
	return NULL;
}

/* Worker threads are created BEFORE the ready line, so a capture armed after
   ready sees the complete thread set (the helper refuses a thread-set change). */
static pthread_t pool_th[32];
static struct worker pool_w[32];
static int pool_n;
static void spawn_threads(int n, int variant, uint64_t ns, int cpu) {
	pool_n = n;
	for (int i = 0; i < n; i++) {
		pool_w[i] = (struct worker){.variant = variant, .ns = ns, .cpu = cpu};
		pthread_create(&pool_th[i], NULL, thread_main, &pool_w[i]);
	}
}
static void run_threads(void) {
	atomic_store(&go_flag, 1);
	while (atomic_load(&finished_workers) < pool_n) usleep(1000);
	if (pinned_contention) {
		/* pinned contention: runnable delay is wall minus on-CPU time per thread */
		for (int i = 0; i < pool_n; i++) {
			uint64_t delay = pool_w[i].wall > pool_w[i].cpu_ns ? pool_w[i].wall - pool_w[i].cpu_ns : 0;
			emit("runnable_delay", 0, delay, 0, pool_w[i].wall);
			if (delay * 10 < pool_w[i].wall) fail(); /* contention must cost >= 10 percent */
		}
	}
}

static void release_threads(void) {
	atomic_store(&exit_flag, 1);
	for (int i = 0; i < pool_n; i++) pthread_join(pool_th[i], NULL);
}

/* ---- blocking intervals, each measured by this program ---- */
#define MS 1000000ull
static void interval(const char *kind, uint64_t t0, uint64_t t1, uint64_t expect) {
	emit(kind, t0, t1, expect, 0);
	if (t1 - t0 < expect || t1 - t0 > expect + 250 * MS) fail();
}
static void block_sleep(void) {
	struct timespec req = {0, 200 * 1000000};
	uint64_t t0 = now_ns();
	nanosleep(&req, NULL);
	interval("timed_sleep", t0, now_ns(), 200 * MS);
}
/* The foreign process is forked once, BEFORE the ready line: a fork inside a live
   capture is a coverage change for the helper. It wakes the target on request. */
static int cmd_pipe[2], wake_pipe[2];
static _Atomic int *fx_word;
static pid_t waker;
static void start_waker(void) {
	fx_word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fx_word == MAP_FAILED || pipe(cmd_pipe) != 0 || pipe(wake_pipe) != 0) {
		fail();
		return;
	}
	waker = fork();
	if (waker == 0) {
		close(cmd_pipe[1]);
		close(wake_pipe[0]);
		char c;
		while (read(cmd_pipe[0], &c, 1) == 1) {
			usleep(50 * 1000);
			if (c == 112) {
				(void)!write(wake_pipe[1], "x", 1);
			} else {
				atomic_store(fx_word, 1);
				syscall(SYS_futex, fx_word, FUTEX_WAKE, 1, NULL, NULL, 0);
			}
		}
		_exit(0);
	}
	close(cmd_pipe[0]);
	close(wake_pipe[1]);
}
static void block_pipe(void) {
	char b;
	(void)!write(cmd_pipe[1], "p", 1);
	uint64_t t0 = now_ns();
	ssize_t n = read(wake_pipe[0], &b, 1);
	uint64_t t1 = now_ns();
	if (n != 1) fail();
	interval("pipe_wait", t0, t1, 40 * MS);
}
static void block_futex(void) {
	atomic_store(fx_word, 0);
	(void)!write(cmd_pipe[1], "f", 1);
	uint64_t t0 = now_ns();
	while (atomic_load(fx_word) == 0) syscall(SYS_futex, fx_word, FUTEX_WAIT, 0, NULL, NULL, 0);
	uint64_t t1 = now_ns();
	interval("futex_wait", t0, t1, 40 * MS);
}
static void run_blocking(uint64_t ns) {
	/* 8 rounds of 3 interval kinds = 24 intervals; repeat until the time is used up */
	uint64_t deadline = now_ns() + ns;
	int rounds = 0;
	while (rounds < 8 || now_ns() < deadline) {
		block_sleep();
		block_pipe();
		block_futex();
		rounds++;
		if (rounds >= 64) break;
	}
}

static void run_migrate(uint64_t ns) {
	cpu_set_t all;
	sched_getaffinity(0, sizeof all, &all);
	int cpus[256], n = 0;
	for (int c = 0; c < 256 && c < CPU_SETSIZE; c++)
		if (CPU_ISSET(c, &all)) cpus[n++] = c;
	uint64_t deadline = now_ns() + ns, x = 1;
	int moves = 0, last = -1;
	unsigned long seen[4] = {0};
	for (int i = 0; now_ns() < deadline; i++) {
		if (n > 1) {
			cpu_set_t one;
			CPU_ZERO(&one);
			CPU_SET(cpus[i % n], &one);
			sched_setaffinity(0, sizeof one, &one);
		}
		uint64_t until = now_ns() + 25 * MS;
		while (now_ns() < until) x = spqual_serve(x);
		int cur = sched_getcpu();
		if (cur >= 0 && cur < 256) seen[cur / 64] |= 1ul << (cur % 64);
		if (cur != last && last >= 0) moves++;
		last = cur;
	}
	sink ^= x;
	int distinct = 0;
	for (int i = 0; i < 4; i++) distinct += __builtin_popcountl(seen[i]);
	emit("migration", 0, 0, 0, (uint64_t)moves << 32 | (uint64_t)distinct);
	if (n > 1 && (distinct < 2 || moves < 2)) fail();
}

int main(int argc, char **argv) {
	if (argc < 5) {
		fprintf(stderr, "usage: workloads <mode> <ground-truth-file> <seconds> <nonce>\n");
		return 2;
	}
	mode_name = argv[1];
	uint64_t ns = (uint64_t)(atof(argv[3]) * 1e9);
	snprintf(nonce, sizeof nonce, "%s", argv[4]);
	char stack_canary[80];
	snprintf(stack_canary, sizeof stack_canary, "stk%.60s", nonce);
	setenv("SPQUAL_CANARY", nonce, 1);
	int after_exec = argc >= 6 && strcmp(argv[5], "after-exec") == 0;
	gt = fopen(argv[2], "a");
	if (!gt) return 2;
	name_thread("main");
	if (!strcmp(mode_name, "cpu")) spawn_threads(1, 0, ns, -1);
	else if (!strcmp(mode_name, "nofp")) spawn_threads(1, 1, ns, -1);
	else if (!strcmp(mode_name, "fanout")) spawn_threads(16, 0, ns, -1);
	else if (!strcmp(mode_name, "contend")) {
		cpu_set_t all;
		sched_getaffinity(0, sizeof all, &all);
		int cpu = 0;
		while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &all)) cpu++;
		expect_hot = 0;
		pinned_contention = 1;
		spawn_threads(2, 0, ns, cpu);
	} else if (!strcmp(mode_name, "exec")) {
		if (after_exec) spawn_threads(1, 2, ns, -1);
		else spawn_threads(1, 0, ns / 2, -1);
	} else if (!strcmp(mode_name, "blocking")) {
		start_waker();
	} else if (strcmp(mode_name, "migrate")) {
		fprintf(stderr, "unknown mode\n");
		return 2;
	}
	if (!after_exec) {
		printf("ready %d\n", (int)getpid());
		fflush(stdout);
		char line[8];
		if (!fgets(line, sizeof line, stdin) || strncmp(line, "go", 2) != 0) return 2;
	}
	uint64_t t0 = now_ns();
	if (!strcmp(mode_name, "blocking")) run_blocking(ns);
	else if (!strcmp(mode_name, "migrate")) run_migrate(ns);
	else if (!strcmp(mode_name, "exec") && !after_exec) {
		run_threads();
		emit("exec", now_ns(), now_ns(), 0, 1);
		fclose(gt);
		char secs[32];
		snprintf(secs, sizeof secs, "%.3f", (double)ns / 2e9);
		execl("/proc/self/exe", argv[0], "exec", argv[2], secs, nonce, "after-exec", (char *)NULL);
		return 2;
	} else run_threads();
	int bad = atomic_load(&failures);
	pthread_mutex_lock(&gt_lock);
	fprintf(gt, "{\"mode\":\"%s\",\"kind\":\"summary\",\"pid\":%d,\"self_verified\":%s,\"failures\":%d,\"start_ns\":%llu,\"end_ns\":%llu,\"canary_len\":%d}\n", mode_name, (int)getpid(), bad == 0 ? "true" : "false", bad, (unsigned long long)t0, (unsigned long long)now_ns(), (int)strlen(stack_canary));
	fclose(gt);
	pthread_mutex_unlock(&gt_lock);
	/* Stay alive (idle) until the verifier has stopped its capture, so the target
	   never exits underneath a live scheduler session. */
	printf("done\n");
	fflush(stdout);
	char tail[8];
	(void)!fgets(tail, sizeof tail, stdin);
	release_threads();
	if (waker > 0) {
		close(cmd_pipe[1]);
		waitpid(waker, NULL, 0);
	}
	return bad == 0 ? 0 : 3;
}
