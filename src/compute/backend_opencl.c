/*
 * backend_opencl.c — OpenCL compute backend
 *
 * Cross-platform GPU compute: macOS, Linux, Windows.
 * Uses OpenCL 1.2 for maximum compatibility.
 *
 * On macOS: links against OpenCL.framework (deprecated but functional).
 * On Linux: links against libOpenCL.so (from GPU driver / mesa).
 * On Windows: links against OpenCL.lib (from GPU vendor SDK).
 */

#include "compute_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(__APPLE__)
#include <OpenCL/opencl.h>
#define CC_OPENCL_AVAILABLE 1
#elif __has_include(<CL/cl.h>)
#include <CL/cl.h>
#define CC_OPENCL_AVAILABLE 1
#else
#define CC_OPENCL_AVAILABLE 0
#endif

#if CC_OPENCL_AVAILABLE

/* ── OpenCL context ── */

typedef struct {
    cl_platform_id   platform;
    cl_device_id     device;
    cl_context       context;
    cl_command_queue  queue;
} ocl_ctx;

typedef struct {
    cl_program program;
    cl_kernel  kernel;
    ocl_ctx   *ctx;
} ocl_kernel;

/* ── Backend implementation ── */

static void *ocl_create(void)
{
    ocl_ctx *c = calloc(1, sizeof(ocl_ctx));
    if (!c) return NULL;

    /* get first GPU platform + device */
    cl_uint np = 0;
    clGetPlatformIDs(0, NULL, &np);
    if (np == 0) { free(c); return NULL; }

    cl_platform_id *platforms = malloc(np * sizeof(cl_platform_id));
    clGetPlatformIDs(np, platforms, NULL);

    int found = 0;
    for (cl_uint i = 0; i < np && !found; i++) {
        cl_uint nd = 0;
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 0, NULL, &nd);
        if (nd > 0) {
            c->platform = platforms[i];
            clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 1, &c->device, NULL);
            found = 1;
        }
    }
    free(platforms);

    if (!found) {
        /* fall back to any device (CPU OpenCL) */
        cl_uint nd = 0;
        clGetPlatformIDs(1, &c->platform, NULL);
        clGetDeviceIDs(c->platform, CL_DEVICE_TYPE_ALL, 1, &c->device, &nd);
        if (nd == 0) { free(c); return NULL; }
    }

    cl_int err;
    c->context = clCreateContext(NULL, 1, &c->device, NULL, NULL, &err);
    if (err != CL_SUCCESS) { free(c); return NULL; }

#ifdef CL_VERSION_2_0
    c->queue = clCreateCommandQueueWithProperties(c->context, c->device, NULL, &err);
#else
    c->queue = clCreateCommandQueue(c->context, c->device, 0, &err);
#endif
    if (err != CL_SUCCESS) { clReleaseContext(c->context); free(c); return NULL; }

    return c;
}

static void ocl_destroy(void *impl)
{
    ocl_ctx *c = impl;
    if (!c) return;
    if (c->queue) clReleaseCommandQueue(c->queue);
    if (c->context) clReleaseContext(c->context);
    free(c);
}

static int ocl_device_info(void *impl, cc_device_info *info)
{
    ocl_ctx *c = impl;
    memset(info, 0, sizeof(*info));
    info->backend = CC_COMPUTE_OPENCL;
    clGetDeviceInfo(c->device, CL_DEVICE_NAME, sizeof(info->name), info->name, NULL);

    cl_ulong mem = 0;
    clGetDeviceInfo(c->device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem), &mem, NULL);
    info->memory = mem;

    cl_uint cu = 0;
    clGetDeviceInfo(c->device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cu), &cu, NULL);
    info->compute_units = cu;

    size_t wg = 0;
    clGetDeviceInfo(c->device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(wg), &wg, NULL);
    info->max_workgroup = (uint32_t)wg;

    return 0;
}

static void *ocl_buf_create(void *impl, size_t size)
{
    ocl_ctx *c = impl;
    cl_int err;
    cl_mem buf = clCreateBuffer(c->context, CL_MEM_READ_WRITE, size, NULL, &err);
    return (err == CL_SUCCESS) ? (void *)buf : NULL;
}

static void *ocl_buf_create_from(void *impl, const void *data, size_t size)
{
    ocl_ctx *c = impl;
    cl_int err;
    cl_mem buf = clCreateBuffer(c->context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                size, (void *)data, &err);
    return (err == CL_SUCCESS) ? (void *)buf : NULL;
}

static int ocl_buf_upload(void *impl, void *buf, const void *data, size_t size)
{
    ocl_ctx *c = impl;
    return clEnqueueWriteBuffer(c->queue, (cl_mem)buf, CL_TRUE, 0, size, data, 0, NULL, NULL)
           == CL_SUCCESS ? 0 : -1;
}

static int ocl_buf_download(void *impl, void *buf, void *data, size_t size)
{
    ocl_ctx *c = impl;
    return clEnqueueReadBuffer(c->queue, (cl_mem)buf, CL_TRUE, 0, size, data, 0, NULL, NULL)
           == CL_SUCCESS ? 0 : -1;
}

static void ocl_buf_destroy(void *impl, void *buf)
{
    (void)impl;
    if (buf) clReleaseMemObject((cl_mem)buf);
}

static void *ocl_kernel_compile(void *impl, const char *source, const char *entry)
{
    ocl_ctx *c = impl;
    cl_int err;

    const size_t len = strlen(source);
    cl_program prog = clCreateProgramWithSource(c->context, 1, &source, &len, &err);
    if (err != CL_SUCCESS) return NULL;

    err = clBuildProgram(prog, 1, &c->device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        /* dump build log for debugging */
        size_t log_len = 0;
        clGetProgramBuildInfo(prog, c->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_len);
        if (log_len > 1) {
            char *log = malloc(log_len);
            clGetProgramBuildInfo(prog, c->device, CL_PROGRAM_BUILD_LOG, log_len, log, NULL);
            fprintf(stderr, "OpenCL build error:\n%s\n", log);
            free(log);
        }
        clReleaseProgram(prog);
        return NULL;
    }

    cl_kernel kern = clCreateKernel(prog, entry, &err);
    if (err != CL_SUCCESS) { clReleaseProgram(prog); return NULL; }

    ocl_kernel *k = calloc(1, sizeof(ocl_kernel));
    k->program = prog;
    k->kernel = kern;
    k->ctx = c;
    return k;
}

static int ocl_kernel_set_buf(void *impl, void *kernel, int idx, void *buf)
{
    (void)impl;
    ocl_kernel *k = kernel;
    cl_mem m = (cl_mem)buf;
    return clSetKernelArg(k->kernel, (cl_uint)idx, sizeof(cl_mem), &m) == CL_SUCCESS ? 0 : -1;
}

static int ocl_kernel_set_bytes(void *impl, void *kernel, int idx, const void *data, size_t size)
{
    (void)impl;
    ocl_kernel *k = kernel;
    return clSetKernelArg(k->kernel, (cl_uint)idx, size, data) == CL_SUCCESS ? 0 : -1;
}

static int ocl_dispatch(void *impl, void *kernel, uint32_t count)
{
    ocl_ctx *c = impl;
    ocl_kernel *k = kernel;
    size_t global = count;
    size_t local = 256;
    if (local > global) local = global;
    /* round global up to multiple of local */
    global = ((global + local - 1) / local) * local;
    return clEnqueueNDRangeKernel(c->queue, k->kernel, 1, NULL, &global, &local, 0, NULL, NULL)
           == CL_SUCCESS ? 0 : -1;
}

static int ocl_dispatch_2d(void *impl, void *kernel, uint32_t w, uint32_t h)
{
    ocl_ctx *c = impl;
    ocl_kernel *k = kernel;
    size_t global[2] = { w, h };
    size_t local[2] = { 16, 16 };
    if (local[0] > global[0]) local[0] = global[0];
    if (local[1] > global[1]) local[1] = global[1];
    global[0] = ((global[0] + local[0] - 1) / local[0]) * local[0];
    global[1] = ((global[1] + local[1] - 1) / local[1]) * local[1];
    return clEnqueueNDRangeKernel(c->queue, k->kernel, 2, NULL, global, local, 0, NULL, NULL)
           == CL_SUCCESS ? 0 : -1;
}

static int ocl_finish(void *impl)
{
    ocl_ctx *c = impl;
    return clFinish(c->queue) == CL_SUCCESS ? 0 : -1;
}

static void ocl_kernel_destroy(void *impl, void *kernel)
{
    (void)impl;
    ocl_kernel *k = kernel;
    if (!k) return;
    if (k->kernel) clReleaseKernel(k->kernel);
    if (k->program) clReleaseProgram(k->program);
    free(k);
}

const cc_backend_vtable cc_opencl_vtable = {
    .create         = ocl_create,
    .destroy        = ocl_destroy,
    .device_info    = ocl_device_info,
    .buf_create     = ocl_buf_create,
    .buf_create_from= ocl_buf_create_from,
    .buf_upload     = ocl_buf_upload,
    .buf_download   = ocl_buf_download,
    .buf_destroy    = ocl_buf_destroy,
    .kernel_compile = ocl_kernel_compile,
    .kernel_set_buf = ocl_kernel_set_buf,
    .kernel_set_bytes = ocl_kernel_set_bytes,
    .dispatch       = ocl_dispatch,
    .dispatch_2d    = ocl_dispatch_2d,
    .finish         = ocl_finish,
    .kernel_destroy = ocl_kernel_destroy,
};

#else /* no OpenCL */

const cc_backend_vtable cc_opencl_vtable = {0};

#endif
