// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
//
// Native-extension workload of the python_trampolines scenario (fixtures/nativeperf/acceptance/scenario_python_trampolines.go):
// a real CPython extension module, spnative, whose burn(seconds) spends its time in native code with the GIL held, the way an
// extension that crunches numbers does. The call chain inside the object is spext_burn -> spext_mix -> spext_hot; the
// verifier resolves sampled addresses against this object's own ELF symbol table, and the product only ever names such a
// frame by the GNU build ID the operator approved.
//
//	cc -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -shared -fPIC -Wl,--build-id -I$(python -c 'import sysconfig;print(sysconfig.get_paths()["include"])') -o spnative.so spnative.c
//
// GCC does not keep a frame for a leaf function that uses no stack even with -mno-omit-leaf-frame-pointer, so spext_hot keeps
// a volatile local: that forces its frame record (push %rbp) and a frame-pointer unwind then names its caller spext_mix
// (without a frame record the unwind skips the caller, the honest frame-pointer limitation, seen as spext_hot <- spext_burn).
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <time.h>

static volatile uint64_t spext_sink;

static uint64_t spext_now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

__attribute__((noinline)) static uint64_t spext_hot(uint64_t x) {
	volatile uint64_t keep = x;
	for (int i = 0; i < 4096; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
		x += (uint64_t)i;
	}
	return x ^ (keep & 0);
}

__attribute__((noinline)) static uint64_t spext_mix(uint64_t x) {
	for (int i = 0; i < 16; i++) {
		x = spext_hot(x) + 0x9e3779b97f4a7c15ull;
	}
	return x;
}

__attribute__((noinline)) static PyObject *spext_burn(PyObject *self, PyObject *args) {
	double seconds;
	if (!PyArg_ParseTuple(args, "d", &seconds)) {
		return NULL;
	}
	uint64_t deadline = spext_now_ns() + (uint64_t)(seconds * 1e9);
	uint64_t x = 88172645463325252ull;
	while (spext_now_ns() < deadline) {
		x = spext_mix(x);
	}
	spext_sink = x;
	return PyLong_FromUnsignedLongLong(x);
}

static PyMethodDef spnative_methods[] = {
	{"burn", spext_burn, METH_VARARGS, "burn(seconds): native CPU work with the GIL held"},
	{NULL, NULL, 0, NULL},
};

static struct PyModuleDef spnative_module = {PyModuleDef_HEAD_INIT, "spnative", NULL, -1, spnative_methods};

PyMODINIT_FUNC PyInit_spnative(void) { return PyModule_Create(&spnative_module); }
