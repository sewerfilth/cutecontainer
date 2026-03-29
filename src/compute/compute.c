/*
 * compute.c — cross-platform GPU compute abstraction
 *
 * Backend priority: Metal → OpenCL → CPU
 * Each backend is in its own file; this file handles dispatch + probing.
 */

#include "compute_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <dirent.h>
#else
#include <windows.h>
#endif

/* ── Backend availability (set by compile flags) ── */

#if defined(__APPLE__)
#define CC_HAS_METAL 1
#define CC_HAS_OPENCL 1  /* macOS has OpenCL (deprecated but functional) */
#else
#define CC_HAS_METAL 0
#endif

#if !defined(CC_HAS_OPENCL)
/* check if OpenCL headers are available */
#if __has_include(<CL/cl.h>) || __has_include(<OpenCL/opencl.h>)
#define CC_HAS_OPENCL 1
#else
#define CC_HAS_OPENCL 0
#endif
#endif

/* ── Platform capability probing ── */

static uint32_t probe_cpu_caps(void)
{
    uint32_t caps = 0;

#if defined(__aarch64__) || defined(__arm64__)
    caps |= CC_PLATFORM_HAS_NEON;
    caps |= CC_PLATFORM_HAS_AESE;
    caps |= CC_PLATFORM_HAS_PMULL;   /* all ARMv8 have PMULL */
    caps |= CC_PLATFORM_HAS_CRC32;
    /* SHA3/SHA512/SVE detection via OS feature registers */
    #if defined(__APPLE__)
    /* Apple Silicon: A14+ and M1+ have SHA3, SHA512 */
    caps |= CC_PLATFORM_HAS_SHA3;
    caps |= CC_PLATFORM_HAS_SHA512;
    #elif defined(__linux__)
    /* Linux: read /proc/cpuinfo or HWCAP2 */
    unsigned long hwcap2 = 0;
    #if __has_include(<sys/auxv.h>)
    #include <sys/auxv.h>
    hwcap2 = getauxval(AT_HWCAP2);
    #endif
    if (hwcap2 & (1 << 17)) caps |= CC_PLATFORM_HAS_SVE;
    if (hwcap2 & (1 << 12)) caps |= CC_PLATFORM_HAS_SHA3;
    if (hwcap2 & (1 << 13)) caps |= CC_PLATFORM_HAS_SHA512;
    #endif

#elif defined(__x86_64__) || defined(_M_X64)
    #if defined(__GNUC__) || defined(__clang__)
    uint32_t eax, ebx, ecx, edx;

    /* leaf 1: AES-NI, SSE4.2 */
    __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a"(1),"c"(0));
    if (ecx & (1 << 25)) caps |= CC_PLATFORM_HAS_AES_NI;
    if (ecx & (1 << 20)) caps |= CC_PLATFORM_HAS_CRC32;  /* SSE4.2 CRC32 */

    /* leaf 7: AVX2, AVX-512, SHA-NI */
    __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a"(7),"c"(0));
    if (ebx & (1 << 5))  caps |= CC_PLATFORM_HAS_AVX2;
    if (ebx & (1 << 16)) caps |= CC_PLATFORM_HAS_AVX512;
    if (ebx & (1 << 29)) caps |= CC_PLATFORM_HAS_SHA_NI;

    #elif defined(_MSC_VER)
    int info[4];
    __cpuidex(info, 1, 0);
    if (info[2] & (1 << 25)) caps |= CC_PLATFORM_HAS_AES_NI;
    if (info[2] & (1 << 20)) caps |= CC_PLATFORM_HAS_CRC32;
    __cpuidex(info, 7, 0);
    if (info[1] & (1 << 5))  caps |= CC_PLATFORM_HAS_AVX2;
    if (info[1] & (1 << 16)) caps |= CC_PLATFORM_HAS_AVX512;
    if (info[1] & (1 << 29)) caps |= CC_PLATFORM_HAS_SHA_NI;
    #endif
#endif

    return caps;
}

static uint32_t probe_nvme_caps(void)
{
    uint32_t caps = 0;

#if defined(__linux__)
    /* check if any NVMe devices exist */
    DIR *d = opendir("/sys/class/nvme");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] != '.') {
                caps |= CC_PLATFORM_HAS_NVME;
                break;
            }
        }
        closedir(d);
    }
#elif defined(__APPLE__)
    /* macOS: NVMe is always present on Apple Silicon */
    #if defined(__aarch64__)
    caps |= CC_PLATFORM_HAS_NVME;
    #endif
#elif defined(_WIN32)
    /* Windows: check for NVMe via SetupAPI or WMI — simplified check */
    /* NVMe is nearly universal on modern Windows PCs */
    caps |= CC_PLATFORM_HAS_NVME;
#endif

    return caps;
}

static uint32_t probe_hw_encoder_caps(void)
{
    uint32_t caps = 0;

#if defined(__APPLE__) && defined(__aarch64__)
    caps |= CC_PLATFORM_HAS_PRORES_HW;
#endif

    /* NVENC detection: check for libnvidia-encode or nvidia-smi */
#if defined(__linux__)
    if (access("/dev/nvidia0", F_OK) == 0) {
        caps |= CC_PLATFORM_HAS_NVENC;
        caps |= CC_PLATFORM_HAS_NVDEC;
        caps |= CC_PLATFORM_HAS_CUDA;
    }
#elif defined(_WIN32)
    /* check for nvEncodeAPI64.dll */
    HMODULE nv = LoadLibraryA("nvEncodeAPI64.dll");
    if (nv) { caps |= CC_PLATFORM_HAS_NVENC; FreeLibrary(nv); }
    nv = LoadLibraryA("nvcuvid.dll");
    if (nv) { caps |= CC_PLATFORM_HAS_NVDEC; FreeLibrary(nv); }
    nv = LoadLibraryA("nvcuda.dll");
    if (nv) { caps |= CC_PLATFORM_HAS_CUDA; FreeLibrary(nv); }
#endif

    /* Intel QSV: check for VA-API (Linux) or MFX (Windows) */
#if defined(__linux__)
    if (access("/dev/dri/renderD128", F_OK) == 0) {
        /* heuristic: Intel iGPU present */
        caps |= CC_PLATFORM_HAS_QSV;
    }
#endif

    return caps;
}

uint32_t cc_compute_probe(void)
{
    uint32_t caps = probe_cpu_caps();

#if CC_HAS_METAL
    caps |= CC_PLATFORM_HAS_METAL;
#endif

#if CC_HAS_OPENCL
    caps |= CC_PLATFORM_HAS_OPENCL;
#endif

    /* TODO: Vulkan probe via vkEnumerateInstanceExtensionProperties */

    caps |= probe_nvme_caps();
    caps |= probe_hw_encoder_caps();

    return caps;
}

/* ── Compute context (backend-agnostic) ── */

struct cc_compute_ctx {
    cc_compute_backend backend;
    void              *impl;    /* backend-specific handle */
};

struct cc_compute_buf {
    cc_compute_ctx *ctx;
    void           *impl;
    size_t          size;
};

struct cc_compute_kernel {
    cc_compute_ctx *ctx;
    void           *impl;
};

/* ── Backend dispatch ── */

static const cc_backend_vtable *get_vtable(cc_compute_backend b)
{
    switch (b) {
#if CC_HAS_METAL
    case CC_COMPUTE_METAL:  return &cc_metal_vtable;
#endif
#if CC_HAS_OPENCL
    case CC_COMPUTE_OPENCL: return &cc_opencl_vtable;
#endif
    case CC_COMPUTE_CPU:    return &cc_cpu_vtable;
    default:                return NULL;
    }
}

/* ── Public API ── */

int cc_compute_device_info(cc_device_info *info)
{
    if (!info) return -1;
    memset(info, 0, sizeof(*info));
    info->backend = CC_COMPUTE_CPU;
    info->platform_caps = cc_compute_probe();
    snprintf(info->name, sizeof(info->name), "CPU");
    return 0;
}

cc_compute_ctx *cc_compute_create(void)
{
    /* try backends in priority order */
#if CC_HAS_METAL
    cc_compute_ctx *c = cc_compute_create_with(CC_COMPUTE_METAL);
    if (c) return c;
#endif
#if CC_HAS_OPENCL
    cc_compute_ctx *c2 = cc_compute_create_with(CC_COMPUTE_OPENCL);
    if (c2) return c2;
#endif
    return cc_compute_create_with(CC_COMPUTE_CPU);
}

cc_compute_ctx *cc_compute_create_with(cc_compute_backend backend)
{
    const cc_backend_vtable *vt = get_vtable(backend);
    if (!vt) return NULL;

    void *impl = vt->create();
    if (!impl && backend != CC_COMPUTE_CPU) return NULL;

    cc_compute_ctx *ctx = calloc(1, sizeof(cc_compute_ctx));
    if (!ctx) { if (impl && vt->destroy) vt->destroy(impl); return NULL; }
    ctx->backend = backend;
    ctx->impl = impl;
    return ctx;
}

cc_compute_backend cc_compute_get_backend(const cc_compute_ctx *ctx)
{
    return ctx ? ctx->backend : CC_COMPUTE_CPU;
}

cc_compute_buf *cc_compute_buf_create(cc_compute_ctx *ctx, size_t size)
{
    if (!ctx) return NULL;
    const cc_backend_vtable *vt = get_vtable(ctx->backend);
    void *impl = vt->buf_create(ctx->impl, size);
    if (!impl) return NULL;
    cc_compute_buf *b = calloc(1, sizeof(cc_compute_buf));
    b->ctx = ctx; b->impl = impl; b->size = size;
    return b;
}

cc_compute_buf *cc_compute_buf_create_from(cc_compute_ctx *ctx, const void *data, size_t size)
{
    if (!ctx) return NULL;
    const cc_backend_vtable *vt = get_vtable(ctx->backend);
    void *impl = vt->buf_create_from(ctx->impl, data, size);
    if (!impl) return NULL;
    cc_compute_buf *b = calloc(1, sizeof(cc_compute_buf));
    b->ctx = ctx; b->impl = impl; b->size = size;
    return b;
}

int cc_compute_buf_upload(cc_compute_buf *buf, const void *data, size_t size)
{
    if (!buf) return -1;
    const cc_backend_vtable *vt = get_vtable(buf->ctx->backend);
    return vt->buf_upload(buf->ctx->impl, buf->impl, data, size);
}

int cc_compute_buf_download(cc_compute_buf *buf, void *data, size_t size)
{
    if (!buf) return -1;
    const cc_backend_vtable *vt = get_vtable(buf->ctx->backend);
    return vt->buf_download(buf->ctx->impl, buf->impl, data, size);
}

void cc_compute_buf_destroy(cc_compute_buf *buf)
{
    if (!buf) return;
    const cc_backend_vtable *vt = get_vtable(buf->ctx->backend);
    vt->buf_destroy(buf->ctx->impl, buf->impl);
    free(buf);
}

cc_compute_kernel *cc_compute_kernel_compile(cc_compute_ctx *ctx,
                                              const char *source,
                                              const char *entry_point)
{
    if (!ctx) return NULL;
    const cc_backend_vtable *vt = get_vtable(ctx->backend);
    void *impl = vt->kernel_compile(ctx->impl, source, entry_point);
    if (!impl) return NULL;
    cc_compute_kernel *k = calloc(1, sizeof(cc_compute_kernel));
    k->ctx = ctx; k->impl = impl;
    return k;
}

int cc_compute_kernel_set_buf(cc_compute_kernel *k, int index, cc_compute_buf *buf)
{
    if (!k || !buf) return -1;
    const cc_backend_vtable *vt = get_vtable(k->ctx->backend);
    return vt->kernel_set_buf(k->ctx->impl, k->impl, index, buf->impl);
}

int cc_compute_kernel_set_bytes(cc_compute_kernel *k, int index, const void *data, size_t size)
{
    if (!k) return -1;
    const cc_backend_vtable *vt = get_vtable(k->ctx->backend);
    return vt->kernel_set_bytes(k->ctx->impl, k->impl, index, data, size);
}

int cc_compute_dispatch(cc_compute_kernel *k, uint32_t count)
{
    if (!k) return -1;
    const cc_backend_vtable *vt = get_vtable(k->ctx->backend);
    return vt->dispatch(k->ctx->impl, k->impl, count);
}

int cc_compute_dispatch_2d(cc_compute_kernel *k, uint32_t width, uint32_t height)
{
    if (!k) return -1;
    const cc_backend_vtable *vt = get_vtable(k->ctx->backend);
    return vt->dispatch_2d(k->ctx->impl, k->impl, width, height);
}

int cc_compute_finish(cc_compute_ctx *ctx)
{
    if (!ctx) return -1;
    const cc_backend_vtable *vt = get_vtable(ctx->backend);
    return vt->finish(ctx->impl);
}

void cc_compute_kernel_destroy(cc_compute_kernel *k)
{
    if (!k) return;
    const cc_backend_vtable *vt = get_vtable(k->ctx->backend);
    vt->kernel_destroy(k->ctx->impl, k->impl);
    free(k);
}

void cc_compute_destroy(cc_compute_ctx *ctx)
{
    if (!ctx) return;
    const cc_backend_vtable *vt = get_vtable(ctx->backend);
    if (vt->destroy) vt->destroy(ctx->impl);
    free(ctx);
}
