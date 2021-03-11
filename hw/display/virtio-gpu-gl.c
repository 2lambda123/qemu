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
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "hw/virtio/virtio.h"
#ifdef CONFIG_ANDROID
#include "hw/virtio/virtio-goldfish-pipe.h"
#endif
#include "hw/virtio/virtio-gpu.h"
#include "hw/virtio/virtio-gpu-bswap.h"
#include "hw/virtio/virtio-gpu-pixman.h"
#include "hw/qdev-properties.h"

#include "hw/virtio/virtio-gpu-virgl.h"

static void virtio_gpu_gl_update_cursor_data(VirtIOGPU *g,
                                             struct virtio_gpu_scanout *s,
                                             uint32_t resource_id)
{
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);
    uint32_t width, height;
    uint32_t pixels, *data;

    data = gl->virgl->virgl_renderer_get_cursor_data(resource_id, &width, &height);
    if (!data) {
        return;
    }

    if (width != s->current_cursor->width ||
        height != s->current_cursor->height) {
        free(data);
        return;
    }

    pixels = s->current_cursor->width * s->current_cursor->height;
    memcpy(s->current_cursor->data, data, pixels * sizeof(uint32_t));
    free(data);
}

static void virtio_gpu_gl_flushed(VirtIOGPUBase *b)
{
    VirtIOGPU *g = VIRTIO_GPU(b);

    virtio_gpu_process_cmdq(g);
}

static void virtio_gpu_gl_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(vdev);
    struct virtio_gpu_ctrl_command *cmd;

    if (!virtio_queue_ready(vq)) {
        return;
    }

    if (!gl->renderer_inited) {
        virtio_gpu_virgl_init(g);
        gl->renderer_inited = true;
    }
    if (gl->renderer_reset) {
        gl->renderer_reset = false;
        virtio_gpu_virgl_reset(g);
    }

    cmd = virtqueue_pop(vq, sizeof(struct virtio_gpu_ctrl_command));
    while (cmd) {
        cmd->vq = vq;
        cmd->error = 0;
        cmd->finished = false;
        QTAILQ_INSERT_TAIL(&g->cmdq, cmd, next);
        cmd = virtqueue_pop(vq, sizeof(struct virtio_gpu_ctrl_command));
    }

    virtio_gpu_process_cmdq(g);
    virtio_gpu_virgl_fence_poll(g);
}

static void virtio_gpu_gl_reset(VirtIODevice *vdev)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(vdev);

    virtio_gpu_reset(vdev);

    /*
     * GL functions must be called with the associated GL context in main
     * thread, and when the renderer is unblocked.
     */
    if (gl->renderer_inited && !gl->renderer_reset) {
        virtio_gpu_virgl_reset_scanout(g);
        gl->renderer_reset = true;
    }
}

static int virtio_gpu_gl_save(QEMUFile *f, void *opaque, size_t size,
                              const VMStateField *field, JSONWriter *vmdesc)
{
    VirtIOGPU *g = opaque;
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);

    if (gl->virgl->virgl_renderer_save_snapshot) {
        // First save the renderer state, then the ram slots, because when we
        // load, the renderer state and host pointers backing blob resources
        // need to be restored first before the ram slots corresponding to the
        // blob resources themselves.
        gl->virgl->virgl_renderer_save_snapshot(f);
#ifdef CONFIG_ANDROID
        virtio_gpu_save_ram_slots(f, g);
#endif
    }

    return virtio_gpu_save(f, opaque, size, field, vmdesc);
}

static int virtio_gpu_gl_load(QEMUFile *f, void *opaque, size_t size,
                              const VMStateField *field)
{
    VirtIOGPU *g = opaque;
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(g);

    if (gl->virgl->virgl_renderer_load_snapshot) {
        gl->virgl->virgl_renderer_load_snapshot(f);
#ifdef CONFIG_ANDROID
        virtio_gpu_load_ram_slots(f, g);
#endif
    }

    return virtio_gpu_load(f, opaque, size, field);
}

static void virtio_gpu_gl_device_realize(DeviceState *qdev, Error **errp)
{
    VirtIOGPU *g = VIRTIO_GPU(qdev);
    VirtIOGPUGL *gl = VIRTIO_GPU_GL(qdev);

#if HOST_BIG_ENDIAN
    error_setg(errp, "virgl is not supported on bigendian platforms");
    return;
#endif

    if (!object_resolve_path_type("", TYPE_VIRTIO_GPU_GL, NULL)) {
        error_setg(errp, "at most one %s device is permitted", TYPE_VIRTIO_GPU_GL);
        return;
    }

    if (!display_opengl) {
        error_setg(errp, "opengl is not available");
        return;
    }

#ifdef CONFIG_ANDROID
    if (virtio_gpu_goldfish_pipe_enabled(g->parent_obj.conf)) {
        gl->virgl = get_goldfish_pipe_virgl_renderer_virtio_interface();
    } else
#endif
    {
        gl->virgl = get_default_virtio_interface();
    }

    g->parent_obj.conf.flags |= (1 << VIRTIO_GPU_FLAG_VIRGL_ENABLED);
    VIRTIO_GPU_BASE(g)->virtio_config.num_capsets =
        virtio_gpu_virgl_get_num_capsets(g);

    virtio_gpu_device_realize(qdev, errp);
}

static Property virtio_gpu_gl_properties[] = {
    DEFINE_PROP_BIT("stats", VirtIOGPU, parent_obj.conf.flags,
                    VIRTIO_GPU_FLAG_STATS_ENABLED, false),
#ifdef CONFIG_ANDROID
    DEFINE_PROP_BIT("goldfish-pipe", VirtIOGPU, parent_obj.conf.flags,
                    VIRTIO_GPU_FLAG_GOLDFISH_PIPE_ENABLED, false),
#endif
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_gpu_gl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);
    VirtIOGPUBaseClass *vbc = VIRTIO_GPU_BASE_CLASS(klass);
    VirtIOGPUClass *vgc = VIRTIO_GPU_CLASS(klass);

    vbc->gl_flushed = virtio_gpu_gl_flushed;
    vgc->handle_ctrl = virtio_gpu_gl_handle_ctrl;
    vgc->process_cmd = virtio_gpu_virgl_process_cmd;
    vgc->update_cursor_data = virtio_gpu_gl_update_cursor_data;
    vgc->gpu_save = virtio_gpu_gl_save;
    vgc->gpu_load = virtio_gpu_gl_load;

    vdc->realize = virtio_gpu_gl_device_realize;
    vdc->reset = virtio_gpu_gl_reset;
    device_class_set_props(dc, virtio_gpu_gl_properties);
}

static const TypeInfo virtio_gpu_gl_info = {
    .name = TYPE_VIRTIO_GPU_GL,
    .parent = TYPE_VIRTIO_GPU,
    .instance_size = sizeof(VirtIOGPUGL),
    .class_init = virtio_gpu_gl_class_init,
};
module_obj(TYPE_VIRTIO_GPU_GL);
module_kconfig(VIRTIO_GPU);

static void virtio_register_types(void)
{
    type_register_static(&virtio_gpu_gl_info);
}

type_init(virtio_register_types)

module_dep("hw-display-virtio-gpu");
