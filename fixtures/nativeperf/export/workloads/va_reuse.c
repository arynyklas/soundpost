/* Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

/* Independently authored executable-code fixture, not a kernel implementation.
 * No machine-code byte strings, process-memory reads or privilege changes.
 * Each function is page-isolated and uses only its own registers/stack. */
__attribute__((noinline, aligned(65536)))
static uint64_t phase_a(uint64_t n) {
    volatile uint64_t v = 17;
    while (n--) v = (v ^ (v << 7)) + 19;
    return 1 + (v == 0);
}
__attribute__((noinline, aligned(65536)))
static uint64_t phase_b(uint64_t n) {
    volatile uint64_t v = 29;
    while (n--) v = (v ^ (v << 9)) + 31;
    return 3 + (v == 0);
}
struct location { uintptr_t address; uint64_t offset; int found; };
static int find_code(struct dl_phdr_info *info, size_t size, void *opaque) {
    (void)size;
    struct location *l = opaque;
    if (info->dlpi_name && info->dlpi_name[0]) return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        uintptr_t start = info->dlpi_addr + p->p_vaddr;
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X) &&
            l->address >= start && l->address - start < p->p_filesz) {
            l->offset = p->p_offset + l->address - start;
            l->found = 1;
            return 1;
        }
    }
    return 0;
}
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || page > 65536) return 2;
    struct location a = { (uintptr_t)phase_a, 0, 0 };
    struct location b = { (uintptr_t)phase_b, 0, 0 };
    dl_iterate_phdr(find_code, &a); dl_iterate_phdr(find_code, &b);
    if (!a.found || !b.found || a.offset == b.offset ||
        a.offset % (uint64_t)page || b.offset % (uint64_t)page) return 3;
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 4;
    void *first = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, (off_t)a.offset);
    void *second = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, (off_t)b.offset);
    close(fd);
    if (first == MAP_FAILED || second == MAP_FAILED) return 5;
    puts("ready"); fflush(stdout);
    if (getchar() != 'a') return 6;
    uint64_t (*hot)(uint64_t) = (uint64_t (*)(uint64_t))first;
    uint64_t result = hot(200000000);
    if (result < 1 || result > 2) return 7;
    puts("phase_a_executed"); fflush(stdout);
    if (getchar() != 'b') return 8;
    void *moved = mremap(second, (size_t)page, (size_t)page, MREMAP_MAYMOVE | MREMAP_FIXED, first);
    if (moved == MAP_FAILED || moved != first) return 9;
    result = hot(200000000);
    if (result < 3 || result > 4) return 10;
    puts("phase_b_same_va_executed"); fflush(stdout);
    if (getchar() != 'q') return 11;
    if (munmap(first, (size_t)page)) return 12;
    return 0;
}
