/*
 * Virtio video device
 *
 * Copyright Red Hat
 *
 * Authors:
 *  Dave Airlie
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-gpu-pci.h"
#include "qom/object.h"
#include "standard-headers/linux/virtio_pci.h"

#define TYPE_VIRTIO_GPU_GL_PCI "virtio-gpu-gl-pci"
typedef struct VirtIOGPUGLPCI VirtIOGPUGLPCI;
DECLARE_INSTANCE_CHECKER(VirtIOGPUGLPCI, VIRTIO_GPU_GL_PCI,
                         TYPE_VIRTIO_GPU_GL_PCI)

struct VirtIOGPUGLPCI {
    VirtIOGPUPCIBase parent_obj;
    VirtIOGPUGL vdev;
};

static void virtio_gpu_pci_gl_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOGPUGLPCI *vgpu = VIRTIO_GPU_GL_PCI(vpci_dev);
    VirtIOGPUGL *gl = &vgpu->vdev;
    VirtIOGPUBase *g = &gl->parent_obj.parent_obj;
    DeviceState *vdev = DEVICE(&vgpu->vdev);
    int i;

    // Cool way to lay things out that should not affect stuff
    // and is compat with the current android11-5.4 kernel:
    // | 0 1 : modern | 2 msix | 4 5 hostshm |
    //
    // This is similar to the crosvm
    // virtio gpu pci bar layout, same except maybe for different msix bar #.
    vpci_dev->modern_mem_bar_idx = 0; // Overwritten: legacy io bar idx
    vpci_dev->msix_bar_idx = 2;
    // Not considered: modern io bar idx (only used in MODERN_PIO_NOTIFY,
    // which doesn't seem to be used in virtio-gpu)
    vpci_dev->hostshm_mem_bar_idx = 4;
    // Note that in future versions of Linux kernels, the bar may be negotiated
    // via some other mechanism based off the shm_cap logic below.

#define VIRTIO_GPU_PCI_HOST_COHERENT_BAR_SIZE (1ULL << 32ULL)

    memory_region_init_ram_user_backed(
        &gl->host_coherent_memory, OBJECT(gl),
        "virtio-gpu-host-coherent",
        VIRTIO_GPU_PCI_HOST_COHERENT_BAR_SIZE);

    // Add shm cap to the guest
    // (Doesn't seem to be used in 5.4, but is a way to be fwd compatible
    // with newer kernels)
    struct virtio_pci_cap64 shm_cap;
    uint32_t mask32 = ~0;

    shm_cap.cap.cap_len = sizeof(shm_cap);
    shm_cap.cap.cfg_type = 8; // PciCapabilityType::SharedMemoryConfig
    shm_cap.cap.bar = vpci_dev->hostshm_mem_bar_idx;

    shm_cap.cap.length =
        cpu_to_le32(mask32 & (int128_get64(gl->host_coherent_memory.size)));
    shm_cap.length_hi =
        cpu_to_le32(mask32 & (int128_get64(gl->host_coherent_memory.size) >> 32ULL));

    shm_cap.cap.offset = mask32 & 0;
    shm_cap.offset_hi = mask32 & 0;

#define VIRTIO_GPU_PCI_CAP_HOSTSHM_ID 1

    shm_cap.cap.id = VIRTIO_GPU_PCI_CAP_HOSTSHM_ID;

    pci_register_bar(&vpci_dev->pci_dev, vpci_dev->hostshm_mem_bar_idx,
            PCI_BASE_ADDRESS_SPACE_MEMORY |
            PCI_BASE_ADDRESS_MEM_TYPE_64, &gl->host_coherent_memory);

    int offset = pci_add_capability(
        &vpci_dev->pci_dev, PCI_CAP_ID_VNDR, 0,
        shm_cap.cap.cap_len, &error_abort);

    // Add the mem cap to virtio-gpu-pci proxy's configuration.
    memcpy(vpci_dev->pci_dev.config + offset + PCI_CAP_FLAGS,
           &shm_cap.cap.cap_len,
           shm_cap.cap.cap_len - PCI_CAP_FLAGS);

    virtio_pci_force_virtio_1(vpci_dev);
    if (!qdev_realize(vdev, BUS(&vpci_dev->bus), errp)) {
        return;
    }

    for (i = 0; i < g->conf.max_outputs; i++) {
        object_property_set_link(OBJECT(g->scanout[i].con), "device",
                                 OBJECT(vpci_dev), &error_abort);
    }
}

static void virtio_gpu_pci_gl_class_init(ObjectClass *klass, void *data)
{
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);

    k->realize = virtio_gpu_pci_gl_realize;
}

static void virtio_gpu_gl_initfn(Object *obj)
{
    VirtIOGPUGLPCI *dev = VIRTIO_GPU_GL_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_GPU_GL);
    VIRTIO_GPU_PCI_BASE(obj)->vgpu = VIRTIO_GPU_BASE(&dev->vdev);
}

static const VirtioPCIDeviceTypeInfo virtio_gpu_gl_pci_info = {
    .generic_name = TYPE_VIRTIO_GPU_GL_PCI,
    .parent = TYPE_VIRTIO_GPU_PCI_BASE,
    .instance_size = sizeof(VirtIOGPUGLPCI),
    .instance_init = virtio_gpu_gl_initfn,
    .class_init = virtio_gpu_pci_gl_class_init,
};
module_obj(TYPE_VIRTIO_GPU_GL_PCI);
module_kconfig(VIRTIO_PCI);

static void virtio_gpu_gl_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_gpu_gl_pci_info);
}

type_init(virtio_gpu_gl_pci_register_types)

module_dep("hw-display-virtio-gpu-pci");
