#ifndef HW_VIRTIO_GPU_VIRGL_H
#define HW_VIRTIO_GPU_VIRGL_H

#include <virglrenderer.h>

struct virgl_renderer_resource_info;

/* Struct of virglrenderer API calls in order to be able to switch between
 * different virgl API impls, or different devices altogether that use
 * the virglrenderer API (e.g., goldfish pipe) */

typedef int (*virgl_renderer_init_t)(
    void *cookie, int flags, struct virgl_renderer_callbacks *cb);
typedef void (*virgl_renderer_poll_t)(void); /* force fences */
typedef void* (*virgl_renderer_get_cursor_data_t)(
    uint32_t resource_id, uint32_t *width, uint32_t *height);
typedef int (*virgl_renderer_resource_create_t)(
    struct virgl_renderer_resource_create_args *args,
    struct iovec *iov, uint32_t num_iovs);
typedef void (*virgl_renderer_resource_unref_t)(uint32_t res_handle);
typedef int (*virgl_renderer_context_create_t)(
    uint32_t handle, uint32_t nlen, const char *name);
typedef void (*virgl_renderer_context_destroy_t)(uint32_t handle);
typedef int (*virgl_renderer_submit_cmd_t)(void *buffer,
                                           int ctx_id,
                                           int ndw);
typedef int (*virgl_renderer_transfer_read_iov_t)(
    uint32_t handle, uint32_t ctx_id,
    uint32_t level, uint32_t stride,
    uint32_t layer_stride,
    struct virgl_box *box,
    uint64_t offset, struct iovec *iov,
    int iovec_cnt);
typedef int (*virgl_renderer_transfer_write_iov_t)(
    uint32_t handle,
    uint32_t ctx_id,
    int level,
    uint32_t stride,
    uint32_t layer_stride,
    struct virgl_box *box,
    uint64_t offset,
    struct iovec *iovec,
    unsigned int iovec_cnt);
typedef void (*virgl_renderer_get_cap_set_t)(uint32_t set, uint32_t *max_ver,
                                             uint32_t *max_size);

typedef void (*virgl_renderer_fill_caps_t)(uint32_t set, uint32_t version,
                                           void *caps);

typedef int (*virgl_renderer_resource_attach_iov_t)(
    int res_handle, struct iovec *iov,
    int num_iovs);
typedef void (*virgl_renderer_resource_detach_iov_t)(
    int res_handle, struct iovec **iov, int *num_iovs);

typedef int (*virgl_renderer_create_fence_t)(
    int client_fence_id, uint32_t ctx_id);

typedef void (*virgl_renderer_force_ctx_0_t)(void);

typedef void (*virgl_renderer_ctx_attach_resource_t)(
    int ctx_id, int res_handle);
typedef void (*virgl_renderer_ctx_detach_resource_t)(
    int ctx_id, int res_handle);
typedef int (*virgl_renderer_resource_get_info_t)(
    int res_handle,
    struct virgl_renderer_resource_info *info);
typedef int (*virgl_renderer_resource_create_v2_t)(unsigned int res_handle, uint64_t hvaId);
typedef int (*virgl_renderer_resource_map_t)(unsigned int res_handle, void** hvaOut, uint64_t* sizeOut);
typedef int (*virgl_renderer_resource_unmap_t)(unsigned int res_handle);

#define LIST_VIRGLRENDERER_API(f) \
f(virgl_renderer_init) \
f(virgl_renderer_poll) \
f(virgl_renderer_get_cursor_data) \
f(virgl_renderer_resource_create) \
f(virgl_renderer_resource_unref) \
f(virgl_renderer_context_create) \
f(virgl_renderer_context_destroy) \
f(virgl_renderer_submit_cmd) \
f(virgl_renderer_transfer_read_iov) \
f(virgl_renderer_transfer_write_iov) \
f(virgl_renderer_get_cap_set) \
f(virgl_renderer_fill_caps) \
f(virgl_renderer_resource_attach_iov) \
f(virgl_renderer_resource_detach_iov) \
f(virgl_renderer_create_fence) \
f(virgl_renderer_force_ctx_0) \
f(virgl_renderer_ctx_attach_resource) \
f(virgl_renderer_ctx_detach_resource) \
f(virgl_renderer_resource_get_info) \
f(virgl_renderer_resource_create_v2) \
f(virgl_renderer_resource_map) \
f(virgl_renderer_resource_unmap) \

#define VIRGLRENDERER_API_DEFINE_STRUCT_FIELD(api) \
    api##_t api;

struct virgl_renderer_virtio_interface {
    LIST_VIRGLRENDERER_API(VIRGLRENDERER_API_DEFINE_STRUCT_FIELD)
};

struct virgl_renderer_virtio_interface* get_default_virtio_interface(void);

extern struct virgl_renderer_virtio_interface *get_goldfish_pipe_virgl_renderer_virtio_interface(void);

#endif /* HW_VIRTIO_GPU_VIRGL_H */
