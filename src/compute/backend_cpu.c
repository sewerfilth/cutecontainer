/*
 * backend_cpu.c — CPU fallback compute backend
 *
 * All operations run on CPU. Buffers are plain heap allocations.
 * "Kernels" are not compiled — this backend exists so the compute
 * abstraction always has something to fall back to.
 */

#include "compute_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void *cpu_create(void) { return (void *)1; /* non-NULL sentinel */ }
static void  cpu_destroy(void *impl) { (void)impl; }

static int cpu_device_info(void *impl, cc_device_info *info) {
    (void)impl;
    memset(info, 0, sizeof(*info));
    info->backend = CC_COMPUTE_CPU;
    snprintf(info->name, sizeof(info->name), "CPU (fallback)");
    info->compute_units = 1;
    return 0;
}

static void *cpu_buf_create(void *impl, size_t size) {
    (void)impl;
    return calloc(1, size);
}

static void *cpu_buf_create_from(void *impl, const void *data, size_t size) {
    (void)impl;
    void *buf = malloc(size);
    if (buf) memcpy(buf, data, size);
    return buf;
}

static int cpu_buf_upload(void *impl, void *buf, const void *data, size_t size) {
    (void)impl;
    memcpy(buf, data, size);
    return 0;
}

static int cpu_buf_download(void *impl, void *buf, void *data, size_t size) {
    (void)impl;
    memcpy(data, buf, size);
    return 0;
}

static void cpu_buf_destroy(void *impl, void *buf) {
    (void)impl;
    free(buf);
}

static void *cpu_kernel_compile(void *impl, const char *src, const char *entry) {
    (void)impl; (void)src; (void)entry;
    return (void *)1; /* no-op for CPU — kernels run as plain C */
}

static int cpu_kernel_set_buf(void *impl, void *k, int idx, void *buf) {
    (void)impl; (void)k; (void)idx; (void)buf;
    return 0;
}

static int cpu_kernel_set_bytes(void *impl, void *k, int idx, const void *data, size_t size) {
    (void)impl; (void)k; (void)idx; (void)data; (void)size;
    return 0;
}

static int cpu_dispatch(void *impl, void *k, uint32_t count) {
    (void)impl; (void)k; (void)count;
    return 0; /* CPU kernels are called directly, not dispatched */
}

static int cpu_dispatch_2d(void *impl, void *k, uint32_t w, uint32_t h) {
    (void)impl; (void)k; (void)w; (void)h;
    return 0;
}

static int cpu_finish(void *impl) { (void)impl; return 0; }

static void cpu_kernel_destroy(void *impl, void *k) { (void)impl; (void)k; }

const cc_backend_vtable cc_cpu_vtable = {
    .create         = cpu_create,
    .destroy        = cpu_destroy,
    .device_info    = cpu_device_info,
    .buf_create     = cpu_buf_create,
    .buf_create_from= cpu_buf_create_from,
    .buf_upload     = cpu_buf_upload,
    .buf_download   = cpu_buf_download,
    .buf_destroy    = cpu_buf_destroy,
    .kernel_compile = cpu_kernel_compile,
    .kernel_set_buf = cpu_kernel_set_buf,
    .kernel_set_bytes = cpu_kernel_set_bytes,
    .dispatch       = cpu_dispatch,
    .dispatch_2d    = cpu_dispatch_2d,
    .finish         = cpu_finish,
    .kernel_destroy = cpu_kernel_destroy,
};
