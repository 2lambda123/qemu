/*
 * Virtio GPU Device
 *
 * Copyright Red Hat, Inc. 2013-2014
 *
 * Authors:
 *     Dave Airlie <airlied@redhat.com>
 *     Gerd Hoffmann <kraxel@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "trace.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-gpu.h"
#include "exec/memory-remap.h"
#include "migration/qemu-file-types.h"

#include "hw/virtio/virtio-gpu-virgl.h"

static struct virgl_renderer_callbacks virtio_gpu_3d_cbs;

static void virgl_cmd_create_resource_2d(VirtIOGPU *g,
                                         struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_create_2d c2d;
    struct virgl_renderer_resource_create_args args;

    VIRTIO_GPU_FILL_CMD(c2d);
    trace_virtio_gpu_cmd_res_create_2d(c2d.resource_id, c2d.format,
                                       c2d.width, c2d.height);

    args.handle = c2d.resource_id;
    args.target = 2;
    args.format = c2d.format;
    args.bind = (1 << 1);
    args.width = c2d.width;
    args.height = c2d.height;
    args.depth = 1;
    args.array_size = 1;
    args.last_level = 0;
    args.nr_samples = 0;
    args.flags = VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP;
    gl->virgl->virgl_renderer_resource_create(&args, NULL, 0);
}

static void virgl_cmd_create_resource_3d(VirtIOGPU *g,
                                         struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_create_3d c3d;
    struct virgl_renderer_resource_create_args args;

    VIRTIO_GPU_FILL_CMD(c3d);
    trace_virtio_gpu_cmd_res_create_3d(c3d.resource_id, c3d.format,
                                       c3d.width, c3d.height, c3d.depth);

    args.handle = c3d.resource_id;
    args.target = c3d.target;
    args.format = c3d.format;
    args.bind = c3d.bind;
    args.width = c3d.width;
    args.height = c3d.height;
    args.depth = c3d.depth;
    args.array_size = c3d.array_size;
    args.last_level = c3d.last_level;
    args.nr_samples = c3d.nr_samples;
    args.flags = c3d.flags;
    gl->virgl->virgl_renderer_resource_create(&args, NULL, 0);
}

static void virgl_cmd_resource_unref(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_unref unref;
    struct iovec *res_iovs = NULL;
    int num_iovs = 0;

    VIRTIO_GPU_FILL_CMD(unref);
    trace_virtio_gpu_cmd_res_unref(unref.resource_id);

    gl->virgl->virgl_renderer_resource_detach_iov(unref.resource_id,
                                       &res_iovs,
                                       &num_iovs);
    if (res_iovs != NULL && num_iovs != 0) {
        virtio_gpu_cleanup_mapping_iov(g, res_iovs, num_iovs);
    }
    gl->virgl->virgl_renderer_resource_unref(unref.resource_id);
}

static void virgl_cmd_context_create(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_ctx_create cc;

    VIRTIO_GPU_FILL_CMD(cc);
    trace_virtio_gpu_cmd_ctx_create(cc.hdr.ctx_id,
                                    cc.debug_name);

    gl->virgl->virgl_renderer_context_create(cc.hdr.ctx_id, cc.nlen,
                                             cc.debug_name);
}

static void virgl_cmd_context_destroy(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_ctx_destroy cd;

    VIRTIO_GPU_FILL_CMD(cd);
    trace_virtio_gpu_cmd_ctx_destroy(cd.hdr.ctx_id);

    gl->virgl->virgl_renderer_context_destroy(cd.hdr.ctx_id);
}

static void virtio_gpu_rect_update(VirtIOGPU *g, int idx, int x, int y,
                                int width, int height)
{
    if (!g->parent_obj.scanout[idx].con) {
        return;
    }

    if (!virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        dpy_gl_update(g->parent_obj.scanout[idx].con, x, y, width, height);
    }
}

static void virgl_cmd_resource_flush(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_resource_flush rf;
    int i;

    VIRTIO_GPU_FILL_CMD(rf);
    trace_virtio_gpu_cmd_res_flush(rf.resource_id,
                                   rf.r.width, rf.r.height, rf.r.x, rf.r.y);

    for (i = 0; i < g->parent_obj.conf.max_outputs; i++) {
        if (g->parent_obj.scanout[i].resource_id != rf.resource_id) {
            continue;
        }
        virtio_gpu_rect_update(g, i, rf.r.x, rf.r.y, rf.r.width, rf.r.height);
#ifdef CONFIG_ANDROID
        if (i == 0 && virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
            stream_renderer_flush_resource_and_readback(rf.resource_id, rf.r.x, rf.r.y,
                                                        rf.r.width, rf.r.height,
                                                        NULL, 0);
        }
#endif
    }
}

static GLuint virgl_borrow_texture_for_scanout(uint32_t id, bool *y_0_top,
                                               uint32_t *width,
                                               uint32_t *height)
{
    struct virgl_renderer_texture_info info;
    int ret;

    memset(&info, 0, sizeof(info));

    ret = virgl_renderer_borrow_texture_for_scanout(id, &info);
    if (ret == -1) {
        return 0;
    }

    if (y_0_top) {
        *y_0_top = info.flags & VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP;
    }

    if (width) {
        *width = info.width;
    }

    if (height) {
        *height = info.height;
    }

    return info.tex_id;
}

static void virgl_cmd_set_scanout(VirtIOGPU *g,
                                  struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_set_scanout ss;

    VIRTIO_GPU_FILL_CMD(ss);
    trace_virtio_gpu_cmd_set_scanout(ss.scanout_id, ss.resource_id,
                                     ss.r.width, ss.r.height, ss.r.x, ss.r.y);

    if (ss.scanout_id >= g->parent_obj.conf.max_outputs) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal scanout id specified %d",
                      __func__, ss.scanout_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
        return;
    }
    g->parent_obj.enable = 1;

    if (ss.resource_id && ss.r.width && ss.r.height) {
        qemu_console_resize(g->parent_obj.scanout[ss.scanout_id].con,
                            ss.r.width, ss.r.height);
        gl->virgl->virgl_renderer_force_ctx_0();
        if (!virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
            dpy_gl_scanout_texture(
                g->parent_obj.scanout[ss.scanout_id].con, ss.resource_id,
                virgl_borrow_texture_for_scanout,
                ss.r.x, ss.r.y, ss.r.width, ss.r.height);
        }
    } else if (!virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        dpy_gfx_replace_surface(
            g->parent_obj.scanout[ss.scanout_id].con, NULL);
        dpy_gl_scanout_disable(g->parent_obj.scanout[ss.scanout_id].con);
    }
    g->parent_obj.scanout[ss.scanout_id].resource_id = ss.resource_id;
}

static void virgl_cmd_submit_3d(VirtIOGPU *g,
                                struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_cmd_submit cs;
    void *buf;
    size_t s;

    VIRTIO_GPU_FILL_CMD(cs);
    trace_virtio_gpu_cmd_ctx_submit(cs.hdr.ctx_id, cs.size);

    buf = g_malloc(cs.size);
    s = iov_to_buf(cmd->elem.out_sg, cmd->elem.out_num,
                   sizeof(cs), buf, cs.size);
    if (s != cs.size) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: size mismatch (%zd/%d)",
                      __func__, s, cs.size);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        goto out;
    }

    if (virtio_gpu_stats_enabled(g->parent_obj.conf)) {
        g->stats.req_3d++;
        g->stats.bytes_3d += cs.size;
    }

    gl->virgl->virgl_renderer_submit_cmd(buf, cs.hdr.ctx_id, cs.size / 4);

out:
    g_free(buf);
}

static void virgl_cmd_transfer_to_host_2d(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_transfer_to_host_2d t2d;
    struct virtio_gpu_box box;

    VIRTIO_GPU_FILL_CMD(t2d);
    trace_virtio_gpu_cmd_res_xfer_toh_2d(t2d.resource_id);

    box.x = t2d.r.x;
    box.y = t2d.r.y;
    box.z = 0;
    box.w = t2d.r.width;
    box.h = t2d.r.height;
    box.d = 1;

    gl->virgl->virgl_renderer_transfer_write_iov(t2d.resource_id,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 (struct virgl_box *)&box,
                                                 t2d.offset, NULL, 0);
}

static void virgl_cmd_transfer_to_host_3d(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_transfer_host_3d t3d;

    VIRTIO_GPU_FILL_CMD(t3d);
    trace_virtio_gpu_cmd_res_xfer_toh_3d(t3d.resource_id);

    gl->virgl->virgl_renderer_transfer_write_iov(t3d.resource_id,
                                                 t3d.hdr.ctx_id,
                                                 t3d.level,
                                                 t3d.stride,
                                                 t3d.layer_stride,
                                                 (struct virgl_box *)&t3d.box,
                                                 t3d.offset, NULL, 0);
}

static void
virgl_cmd_transfer_from_host_3d(VirtIOGPU *g,
                                struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_transfer_host_3d tf3d;

    VIRTIO_GPU_FILL_CMD(tf3d);
    trace_virtio_gpu_cmd_res_xfer_fromh_3d(tf3d.resource_id);

    gl->virgl->virgl_renderer_transfer_read_iov(tf3d.resource_id,
                                                tf3d.hdr.ctx_id,
                                                tf3d.level,
                                                tf3d.stride,
                                                tf3d.layer_stride,
                                                (struct virgl_box *)&tf3d.box,
                                                tf3d.offset, NULL, 0);
}


static void virgl_resource_attach_backing(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_attach_backing att_rb;
    struct iovec *res_iovs;
    uint32_t res_niov;
    int ret;

    VIRTIO_GPU_FILL_CMD(att_rb);
    trace_virtio_gpu_cmd_res_back_attach(att_rb.resource_id);

    ret = virtio_gpu_create_mapping_iov(g, att_rb.nr_entries, sizeof(att_rb),
                                        cmd, NULL, &res_iovs, &res_niov);
    if (ret != 0) {
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        return;
    }

    ret = gl->virgl->virgl_renderer_resource_attach_iov(att_rb.resource_id,
                                                        res_iovs, res_niov);

    if (ret != 0)
        virtio_gpu_cleanup_mapping_iov(g, res_iovs, res_niov);
}

static void virgl_resource_detach_backing(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_detach_backing detach_rb;
    struct iovec *res_iovs = NULL;
    int num_iovs = 0;

    VIRTIO_GPU_FILL_CMD(detach_rb);
    trace_virtio_gpu_cmd_res_back_detach(detach_rb.resource_id);

    gl->virgl->virgl_renderer_resource_detach_iov(detach_rb.resource_id,
                                                  &res_iovs,
                                                  &num_iovs);
    if (res_iovs == NULL || num_iovs == 0) {
        return;
    }
    virtio_gpu_cleanup_mapping_iov(g, res_iovs, num_iovs);
}


static void virgl_cmd_ctx_attach_resource(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_ctx_resource att_res;

    VIRTIO_GPU_FILL_CMD(att_res);
    trace_virtio_gpu_cmd_ctx_res_attach(att_res.hdr.ctx_id,
                                        att_res.resource_id);

    gl->virgl->virgl_renderer_ctx_attach_resource(att_res.hdr.ctx_id, att_res.resource_id);
}

static void virgl_cmd_ctx_detach_resource(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_ctx_resource det_res;

    VIRTIO_GPU_FILL_CMD(det_res);
    trace_virtio_gpu_cmd_ctx_res_detach(det_res.hdr.ctx_id,
                                        det_res.resource_id);

    gl->virgl->virgl_renderer_ctx_detach_resource(det_res.hdr.ctx_id, det_res.resource_id);
}

static void virgl_cmd_get_capset_info(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_get_capset_info info;
    struct virtio_gpu_resp_capset_info resp;

    VIRTIO_GPU_FILL_CMD(info);

    memset(&resp, 0, sizeof(resp));
    if (info.capset_index == 0) {
        resp.capset_id = VIRTIO_GPU_CAPSET_VIRGL;
        gl->virgl->virgl_renderer_get_cap_set(resp.capset_id,
                                              &resp.capset_max_version,
                                              &resp.capset_max_size);
    } else if (info.capset_index == 1) {
        resp.capset_id = VIRTIO_GPU_CAPSET_VIRGL2;
        gl->virgl->virgl_renderer_get_cap_set(resp.capset_id,
                                              &resp.capset_max_version,
                                              &resp.capset_max_size);
    } else {
        resp.capset_max_version = 0;
        resp.capset_max_size = 0;
    }
    resp.hdr.type = VIRTIO_GPU_RESP_OK_CAPSET_INFO;
    virtio_gpu_ctrl_response(g, cmd, &resp.hdr, sizeof(resp));
}

static void virgl_cmd_get_capset(VirtIOGPU *g,
                                 struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_get_capset gc;
    struct virtio_gpu_resp_capset *resp;
    uint32_t max_ver, max_size;
    VIRTIO_GPU_FILL_CMD(gc);

    gl->virgl->virgl_renderer_get_cap_set(gc.capset_id, &max_ver,
                               &max_size);
    if (!max_size) {
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }

    resp = g_malloc0(sizeof(*resp) + max_size);
    resp->hdr.type = VIRTIO_GPU_RESP_OK_CAPSET;
    gl->virgl->virgl_renderer_fill_caps(gc.capset_id,
                                        gc.capset_version,
                                        (void *)resp->capset_data);
    virtio_gpu_ctrl_response(g, cmd, &resp->hdr, sizeof(*resp) + max_size);
    g_free(resp);
}

#ifdef CONFIG_ANDROID

static void virgl_cmd_resource_create_blob(VirtIOGPU *g,
        struct virtio_gpu_ctrl_command* cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_create_blob cb;
    VIRTIO_GPU_FILL_CMD(cb);

    if (!gl->virgl->virgl_renderer_resource_create_v2) {
        fprintf(stderr, "%s: not supported\n", __func__);
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        return;
    }

    gl->virgl->virgl_renderer_resource_create_v2(
        cb.resource_id,
        cb.blob_id);
}

#define VIRTIO_GPU_MAX_RAM_SLOTS 2048

struct VirtioGpuRamSlotInfo {
    int used;
    uint64_t gpa;
    uint64_t offset;
    uint64_t size;
    uint32_t resource_id;
};

struct VirtioGpuRamSlotTable {
    struct VirtioGpuRamSlotInfo slots[VIRTIO_GPU_MAX_RAM_SLOTS];
};

static struct VirtioGpuRamSlotTable* virtio_gpu_ram_slot_table_get(void) {
    static struct VirtioGpuRamSlotTable* s_table;
    if (!s_table) {
        struct VirtioGpuRamSlotTable* table =
            (struct VirtioGpuRamSlotTable*)malloc(sizeof(*table));
        memset(table, 0, sizeof(*table));
        s_table = table;
    }
    return s_table;
}

static int virtio_gpu_ram_slot_infos_first_free_slot() {
    struct VirtioGpuRamSlotTable* table = virtio_gpu_ram_slot_table_get();

    for (int i = 0; i < VIRTIO_GPU_MAX_RAM_SLOTS; ++i) {
        if (0 == table->slots[i].used) return i;
    }
    return -1;
}

static void virtio_gpu_map_slot(
    MemoryRegion* parent, uint32_t resource_id,
    uint64_t gpa, uint64_t offset, void *hva, uint64_t size, int flags) {

    struct VirtioGpuRamSlotTable* table = virtio_gpu_ram_slot_table_get();
    int slot = virtio_gpu_ram_slot_infos_first_free_slot();

    if (slot < 0) {
        fprintf(stderr, "%s: error: no free slots to "
                "map hva %p -> gpa [0x%llx 0x%llx)\n", __func__,
                hva, (unsigned long long)gpa, (unsigned long long)gpa + size);
        return;
    }

    qemu_user_backed_ram_map(gpa, hva, size, USER_BACKED_RAM_FLAGS_READ | USER_BACKED_RAM_FLAGS_WRITE);

    table->slots[slot].gpa = gpa;
    table->slots[slot].offset = offset;
    table->slots[slot].size = size;
    table->slots[slot].used = 1;
    table->slots[slot].resource_id = resource_id;
}

static void virtio_gpu_unmap_slot(
    MemoryRegion* parent, uint32_t resource_id) {

    struct VirtioGpuRamSlotTable* table = virtio_gpu_ram_slot_table_get();

    for (int i = 0; i < VIRTIO_GPU_MAX_RAM_SLOTS; ++i) {
        if (0 == table->slots[i].used) continue;
        if (resource_id != table->slots[i].resource_id) continue;

        qemu_user_backed_ram_unmap(table->slots[i].gpa, table->slots[i].size);
        table->slots[i].used = 0;

        return;
    }
}

static void virgl_cmd_resource_map(VirtIOGPU *g,
        struct virtio_gpu_ctrl_command* cmd) {
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_map_blob m;
    struct virtio_gpu_resp_map_info resp;

    VIRTIO_GPU_FILL_CMD(m);

    void* hva;
    uint64_t size;
    uint64_t offset = m.offset;

    if (!gl->virgl->virgl_renderer_resource_map) {
        fprintf(stderr, "%s: not supported\n", __func__);
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        return;
    }

    gl->virgl->virgl_renderer_resource_map(m.resource_id, &hva, &size);

    if (!hva || !size) {
        fprintf(stderr, "%s: failed for resource %u\n", __func__, m.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
        return;
    }

    uint64_t host_coherent_start =
        object_property_get_uint(OBJECT(&gl->host_coherent_memory), "addr", NULL);

    uint64_t phys_addr =
        host_coherent_start + offset;

    virtio_gpu_map_slot(
        &gl->host_coherent_memory,
        m.resource_id,
        phys_addr,
        offset,
        hva,
        size,
        0xff /* flags, unused */);

    memset(&resp, 0, sizeof(resp));
    resp.hdr.type = VIRTIO_GPU_RESP_OK_MAP_INFO;
    resp.map_info = 0x3;
    resp.padding = 0;
    virtio_gpu_ctrl_response(g, cmd, &resp.hdr, sizeof(resp));
}

static void virgl_cmd_resource_unmap(VirtIOGPU *g,
        struct virtio_gpu_ctrl_command* cmd) {

    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    struct virtio_gpu_resource_unmap_blob u;
    VIRTIO_GPU_FILL_CMD(u);

    if (!gl->virgl->virgl_renderer_resource_unmap) {
        fprintf(stderr, "%s: not supported\n", __func__);
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        return;
    }

    virtio_gpu_unmap_slot(
        &gl->host_coherent_memory,
        u.resource_id);

    gl->virgl->virgl_renderer_resource_unmap(u.resource_id);
}

#endif /* CONFIG_ANDROID */

void virtio_gpu_virgl_process_cmd(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    VIRTIO_GPU_FILL_CMD(cmd->cmd_hdr);

    gl->virgl->virgl_renderer_force_ctx_0();
    switch (cmd->cmd_hdr.type) {
    case VIRTIO_GPU_CMD_CTX_CREATE:
        virgl_cmd_context_create(g, cmd);
        break;
    case VIRTIO_GPU_CMD_CTX_DESTROY:
        virgl_cmd_context_destroy(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
        virgl_cmd_create_resource_2d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:
        virgl_cmd_create_resource_3d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_SUBMIT_3D:
        virgl_cmd_submit_3d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
        virgl_cmd_transfer_to_host_2d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:
        virgl_cmd_transfer_to_host_3d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:
        virgl_cmd_transfer_from_host_3d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
        virgl_resource_attach_backing(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
        virgl_resource_detach_backing(g, cmd);
        break;
    case VIRTIO_GPU_CMD_SET_SCANOUT:
        virgl_cmd_set_scanout(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
        virgl_cmd_resource_flush(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_UNREF:
        virgl_cmd_resource_unref(g, cmd);
        break;
    case VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:
        /* TODO add security */
        virgl_cmd_ctx_attach_resource(g, cmd);
        break;
    case VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:
        /* TODO add security */
        virgl_cmd_ctx_detach_resource(g, cmd);
        break;
    case VIRTIO_GPU_CMD_GET_CAPSET_INFO:
        virgl_cmd_get_capset_info(g, cmd);
        break;
    case VIRTIO_GPU_CMD_GET_CAPSET:
        virgl_cmd_get_capset(g, cmd);
        break;
    case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
        virtio_gpu_get_display_info(g, cmd);
        break;
    case VIRTIO_GPU_CMD_GET_EDID:
        virtio_gpu_get_edid(g, cmd);
        break;
#ifdef CONFIG_ANDROID
    case VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB:
        virgl_cmd_resource_create_blob(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB:
        virgl_cmd_resource_map(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB:
        virgl_cmd_resource_unmap(g, cmd);
        break;
#endif /* CONFIG_ANDROID */
    default:
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        break;
    }

    if (cmd->finished) {
        return;
    }
    if (cmd->error) {
        fprintf(stderr, "%s: ctrl 0x%x, error 0x%x\n", __func__,
                cmd->cmd_hdr.type, cmd->error);
        virtio_gpu_ctrl_response_nodata(g, cmd, cmd->error);
        return;
    }
    if (!(cmd->cmd_hdr.flags & VIRTIO_GPU_FLAG_FENCE)) {
        virtio_gpu_ctrl_response_nodata(g, cmd, VIRTIO_GPU_RESP_OK_NODATA);
        return;
    }

    trace_virtio_gpu_fence_ctrl(cmd->cmd_hdr.fence_id, cmd->cmd_hdr.type);
    gl->virgl->virgl_renderer_create_fence(cmd->cmd_hdr.fence_id, cmd->cmd_hdr.type);
}

static void virgl_write_fence(void *opaque, uint32_t fence)
{
    VirtIOGPU *g = opaque;
    struct virtio_gpu_ctrl_command *cmd, *tmp;

    QTAILQ_FOREACH_SAFE(cmd, &g->fenceq, next, tmp) {
        /*
         * the guest can end up emitting fences out of order
         * so we should check all fenced cmds not just the first one.
         */
        if (cmd->cmd_hdr.fence_id > fence) {
            continue;
        }
        trace_virtio_gpu_fence_resp(cmd->cmd_hdr.fence_id);
        virtio_gpu_ctrl_response_nodata(g, cmd, VIRTIO_GPU_RESP_OK_NODATA);
        QTAILQ_REMOVE(&g->fenceq, cmd, next);
        g_free(cmd);
        g->inflight--;
        if (virtio_gpu_stats_enabled(g->parent_obj.conf)) {
            fprintf(stderr, "inflight: %3d (-)\r", g->inflight);
        }
    }
}

static virgl_renderer_gl_context
virgl_create_context(void *opaque, int scanout_idx,
                     struct virgl_renderer_gl_ctx_param *params)
{
    VirtIOGPU *g = opaque;
    QEMUGLContext ctx;
    QEMUGLParams qparams;

    qparams.major_ver = params->major_ver;
    qparams.minor_ver = params->minor_ver;

    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        fprintf(stderr, "%s: error: tried to use "
                "standard 3d cbs in proxy mode\n", __func__);
        abort();
    }

    ctx = dpy_gl_ctx_create(g->parent_obj.scanout[scanout_idx].con, &qparams);
    return (virgl_renderer_gl_context)ctx;
}

static void virgl_destroy_context(void *opaque, virgl_renderer_gl_context ctx)
{
    VirtIOGPU *g = opaque;
    QEMUGLContext qctx = (QEMUGLContext)ctx;

    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        fprintf(stderr, "%s: error: tried to use "
                "standard 3d cbs in proxy mode\n", __func__);
        abort();
    }

    dpy_gl_ctx_destroy(g->parent_obj.scanout[0].con, qctx);
}

static int virgl_make_context_current(void *opaque, int scanout_idx,
                                      virgl_renderer_gl_context ctx)
{
    VirtIOGPU *g = opaque;
    QEMUGLContext qctx = (QEMUGLContext)ctx;

    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        fprintf(stderr, "%s: error: tried to use "
                "standard 3d cbs in proxy mode\n", __func__);
        abort();
    }

    return dpy_gl_ctx_make_current(g->parent_obj.scanout[scanout_idx].con,
                                   qctx);
}

static struct virgl_renderer_callbacks virtio_gpu_3d_cbs = {
    .version             = 1,
    .write_fence         = virgl_write_fence,
    .create_gl_context   = virgl_create_context,
    .destroy_gl_context  = virgl_destroy_context,
    .make_current        = virgl_make_context_current,
};

static void virtio_gpu_print_stats(void *opaque)
{
    VirtIOGPU *g = opaque;

    if (g->stats.requests) {
        fprintf(stderr, "stats: vq req %4d, %3d -- 3D %4d (%5d)\n",
                g->stats.requests,
                g->stats.max_inflight,
                g->stats.req_3d,
                g->stats.bytes_3d);
        g->stats.requests     = 0;
        g->stats.max_inflight = 0;
        g->stats.req_3d       = 0;
        g->stats.bytes_3d     = 0;
    } else {
        fprintf(stderr, "stats: idle\r");
    }
    timer_mod(g->print_stats, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
}

static void virtio_gpu_fence_poll(void *opaque)
{
    VirtIOGPU *g = opaque;
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);

    gl->virgl->virgl_renderer_poll();
    virtio_gpu_process_cmdq(g);
    if (!QTAILQ_EMPTY(&g->cmdq) || !QTAILQ_EMPTY(&g->fenceq)) {
        timer_mod(g->fence_poll, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 10);
    }
}

void virtio_gpu_virgl_fence_poll(VirtIOGPU *g)
{
    virtio_gpu_fence_poll(g);
}

void virtio_gpu_virgl_reset_scanout(VirtIOGPU *g)
{
    int i;

    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        return;
    }

    for (i = 0; i < g->parent_obj.conf.max_outputs; i++) {
        dpy_gfx_replace_surface(g->parent_obj.scanout[i].con, NULL);
        dpy_gl_scanout_disable(g->parent_obj.scanout[i].con);
    }
}

void virtio_gpu_virgl_reset(VirtIOGPU *g)
{
    virgl_renderer_reset();
}

#ifdef CONFIG_ANDROID
static struct virgl_renderer_callbacks proxy_3d_cbs;
#endif

int virtio_gpu_virgl_init(VirtIOGPU *g)
{
    int ret;

#ifdef CONFIG_ANDROID
    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        ret = virgl_renderer_init(g, 0, &proxy_3d_cbs);
    } else
#endif
    {
        ret = virgl_renderer_init(g, 0, &virtio_gpu_3d_cbs);
    }
    if (ret != 0) {
        error_report("virgl could not be initialized: %d", ret);
        return ret;
    }

    g->fence_poll = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                 virtio_gpu_fence_poll, g);

    if (virtio_gpu_stats_enabled(g->parent_obj.conf)) {
        g->print_stats = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                      virtio_gpu_print_stats, g);
        timer_mod(g->print_stats, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
    }
    return 0;
}

int virtio_gpu_virgl_get_num_capsets(VirtIOGPU *g)
{
    uint32_t capset2_max_ver, capset2_max_size;
    virgl_renderer_get_cap_set(VIRTIO_GPU_CAPSET_VIRGL2,
                              &capset2_max_ver,
                              &capset2_max_size);

    return capset2_max_ver ? 2 : 1;
}

#ifdef CONFIG_ANDROID
static void proxy_virgl_write_fence(void *opaque, uint32_t fence) {
    VirtIOGPU *g = opaque;
    struct virtio_gpu_ctrl_command *cmd, *tmp;

    QTAILQ_FOREACH_SAFE(cmd, &g->fenceq, next, tmp) {
        /*
         * the guest can end up emitting fences out of order
         * so we should check all fenced cmds not just the first one.
         */
        if (cmd->cmd_hdr.fence_id > fence) {
            continue;
        }
        trace_virtio_gpu_fence_resp(cmd->cmd_hdr.fence_id);
        virtio_gpu_ctrl_response_nodata(g, cmd, VIRTIO_GPU_RESP_OK_NODATA);
        QTAILQ_REMOVE(&g->fenceq, cmd, next);
        g_free(cmd);
        g->inflight--;
        if (virtio_gpu_stats_enabled(g->parent_obj.conf)) {
            fprintf(stderr, "inflight: %3d (-)\r", g->inflight);
        }
    }
}

static virgl_renderer_gl_context
proxy_virgl_create_context(void *opaque, int scanout_idx,
                     struct virgl_renderer_gl_ctx_param *params)
{
    return (virgl_renderer_gl_context)0;
}

static void proxy_virgl_destroy_context(
    void *opaque, virgl_renderer_gl_context ctx) { }

static int proxy_virgl_make_context_current(
    void *opaque, int scanout_idx, virgl_renderer_gl_context ctx) { return 0; }

static struct virgl_renderer_callbacks proxy_3d_cbs = {
    .version             = 1,
    .write_fence         = proxy_virgl_write_fence,
    .create_gl_context   = proxy_virgl_create_context,
    .destroy_gl_context  = proxy_virgl_destroy_context,
    .make_current        = proxy_virgl_make_context_current,
#ifdef VIRGL_RENDERER_UNSTABLE_APIS
    .write_context_fence = NULL,
#endif
};
#endif

static struct virgl_renderer_virtio_interface default_virtio_interface = {
    .virgl_renderer_init = virgl_renderer_init,
    .virgl_renderer_poll = virgl_renderer_poll,
    .virgl_renderer_get_cursor_data = virgl_renderer_get_cursor_data,
    .virgl_renderer_resource_create = virgl_renderer_resource_create,
    .virgl_renderer_resource_unref = virgl_renderer_resource_unref,
    .virgl_renderer_context_create = virgl_renderer_context_create,
    .virgl_renderer_context_destroy = virgl_renderer_context_destroy,
    .virgl_renderer_submit_cmd = virgl_renderer_submit_cmd,
    .virgl_renderer_transfer_read_iov = virgl_renderer_transfer_read_iov,
    .virgl_renderer_transfer_write_iov = virgl_renderer_transfer_write_iov,
    .virgl_renderer_get_cap_set = virgl_renderer_get_cap_set,
    .virgl_renderer_fill_caps = virgl_renderer_fill_caps,
    .virgl_renderer_resource_attach_iov = virgl_renderer_resource_attach_iov,
    .virgl_renderer_resource_detach_iov = virgl_renderer_resource_detach_iov,
    .virgl_renderer_create_fence = virgl_renderer_create_fence,
    .virgl_renderer_force_ctx_0 = virgl_renderer_force_ctx_0,
    .virgl_renderer_ctx_attach_resource = virgl_renderer_ctx_attach_resource,
    .virgl_renderer_ctx_detach_resource = virgl_renderer_ctx_detach_resource,
};

struct virgl_renderer_virtio_interface* get_default_virtio_interface() {
    return &default_virtio_interface;
}
