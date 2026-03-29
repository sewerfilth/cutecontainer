/*
 * compute_internal.h — shared vtable definition for compute backends
 */

#ifndef COMPUTE_INTERNAL_H
#define COMPUTE_INTERNAL_H

#include "cutecontainer/compute.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *(*create)(void);
    void  (*destroy)(void *impl);
    int   (*device_info)(void *impl, cc_device_info *info);
    void *(*buf_create)(void *impl, size_t size);
    void *(*buf_create_from)(void *impl, const void *data, size_t size);
    int   (*buf_upload)(void *impl, void *buf, const void *data, size_t size);
    int   (*buf_download)(void *impl, void *buf, void *data, size_t size);
    void  (*buf_destroy)(void *impl, void *buf);
    void *(*kernel_compile)(void *impl, const char *source, const char *entry);
    int   (*kernel_set_buf)(void *impl, void *kernel, int idx, void *buf);
    int   (*kernel_set_bytes)(void *impl, void *kernel, int idx, const void *data, size_t size);
    int   (*dispatch)(void *impl, void *kernel, uint32_t count);
    int   (*dispatch_2d)(void *impl, void *kernel, uint32_t w, uint32_t h);
    int   (*finish)(void *impl);
    void  (*kernel_destroy)(void *impl, void *kernel);
} cc_backend_vtable;

extern const cc_backend_vtable cc_cpu_vtable;
extern const cc_backend_vtable cc_opencl_vtable;
#if defined(__APPLE__)
extern const cc_backend_vtable cc_metal_vtable;
#endif

#endif
