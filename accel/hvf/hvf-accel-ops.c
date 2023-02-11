/*
 * Copyright 2008 IBM Corporation
 *           2008 Red Hat, Inc.
 * Copyright 2011 Intel Corporation
 * Copyright 2016 Veertu, Inc.
 * Copyright 2017 The Android Open Source Project
 *
 * QEMU Hypervisor.framework support
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * This file contain code under public domain from the hvdos project:
 * https://github.com/mist64/hvdos
 *
 * Parts Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "exec/address-spaces.h"
#include "exec/exec-all.h"
#include "sysemu/cpus.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"
#include "sysemu/runstate.h"
#include "qemu/guest-random.h"
#include "hw/boards.h"
#include "exec/memory-remap.h"
#include "exec/ram_addr.h"

HVFState *hvf_state;

/* Memory slots */

#define HVF_MAX_SLOTS 512
#ifdef DEBUG_HVF
#define DPRINTF(fmt, ...) \
    do { fprintf(stdout, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

pthread_rwlock_t mem_lock = PTHREAD_RWLOCK_INITIALIZER;

hvf_slot *hvf_find_overlap_slot(uint64_t start, uint64_t size)
{
    hvf_slot *slot;
    int x;
    for (x = 0; x < hvf_state->num_slots; ++x) {
        slot = &hvf_state->slots[x];
        if (slot->size && start < (slot->start + slot->size) &&
            (start + size) > slot->start) {
            return slot;
        }
    }
    return NULL;
}

struct mac_slot {
    int present;
    uint64_t size;
    uint64_t gpa_start;
    uint64_t gva;
    void *hva;
};

struct mac_slot mac_slots[HVF_MAX_SLOTS];

#define ALIGN(x, y)  (((x) + (y) - 1) & ~((y) - 1))

void *hvf_gpa2hva(uint64_t gpa, bool *found)
{
    struct mac_slot *mslot;
    *found = false;

    for (uint32_t i = 0; i < HVF_MAX_SLOTS; i++) {
        mslot = &mac_slots[i];
        if (!mslot->present) {
            continue;
        }
        if (gpa >= mslot->gpa_start &&
            gpa < mslot->gpa_start + mslot->size) {
            *found = true;
            return (void *)((char *)(mslot->hva) + (gpa - mslot->gpa_start));
        }
    }

    return 0;
}

#define min(a, b) ((a) < (b) ? (a) : (b))
int hvf_hva2gpa(void *hva, uint64_t length, int array_size,
                uint64_t *gpa, uint64_t *size)
{
    struct mac_slot *mslot;
    int count = 0;

    for (uint32_t i = 0; i < HVF_MAX_SLOTS; i++) {
        mslot = &mac_slots[i];
        if (!mslot->present) {
            continue;
        }

        uintptr_t hva_start_num = (uintptr_t)mslot->hva;
        uintptr_t hva_num = (uintptr_t)hva;
        /* Start of this hva region is in this slot. */
        if (hva_num >= hva_start_num &&
            hva_num < hva_start_num + mslot->size) {
            if (count < array_size) {
                gpa[count] = mslot->gpa_start + (hva_num - hva_start_num);
                size[count] = min(length,
                                  mslot->size - (hva_num - hva_start_num));
            }
            count++;
        /**
         * End of this hva region is in this slot.
         * Its start is outside of this slot.
         */
        } else if (hva_num + length <= hva_start_num + mslot->size &&
                   hva_num + length > hva_start_num) {
            if (count < array_size) {
                gpa[count] = mslot->gpa_start;
                size[count] = hva_num + length - hva_start_num;
            }
            count++;
        /* This slot belongs to this hva region completely. */
        } else if (hva_num + length > hva_start_num +  mslot->size &&
                   hva_num < hva_start_num)  {
            if (count < array_size) {
                gpa[count] = mslot->gpa_start;
                size[count] = mslot->size;
            }
            count++;
        }
    }
    return count;
}

static hvf_slot *hvf_next_free_slot(void)
{
    hvf_slot *mem = 0;
    int x;

    for (x = 0; x < hvf_state->num_slots; ++x) {
        mem = &hvf_state->slots[x];
        if (!mem->size) {
            return mem;
        }
    }

    return mem;
}

static int __hvf_set_memory(hvf_slot *slot, hv_memory_flags_t flags);
static int __hvf_set_memory_with_flags_locked(hvf_slot *slot,
                                              hv_memory_flags_t flags);

int hvf_map_safe(void *hva, uint64_t gpa, uint64_t size, uint64_t flags)
{
    pthread_rwlock_wrlock(&mem_lock);
    DPRINTF("%s: hva: [%p 0x%llx] gpa: [0x%llx 0x%llx]\n", __func__,
            hva, (unsigned long long)(uintptr_t)(((char *)hva) + size),
            (unsigned long long)gpa,
            (unsigned long long)gpa + size);

    hvf_slot *mem;
    mem = hvf_find_overlap_slot(gpa, size);

    if (mem &&
        mem->mem == hva &&
        mem->start == gpa &&
        mem->size == size) {

        pthread_rwlock_unlock(&mem_lock);
        return HV_SUCCESS;
    } else if (mem &&
        mem->start == gpa &&
        mem->size == size) {
        /* unmap existing mapping, but only if it coincides */
        mem->size = 0;
        __hvf_set_memory_with_flags_locked(mem, 0);
    } else if (mem) {
        /**
         * TODO: Manage and support partially-overlapping user-backed RAM
         * mappings. for now, consider it fatal.
         */
        pthread_rwlock_unlock(&mem_lock);
        error_report("FATAL: tried to map [0x%llx 0x%llx) to %p "
                   "while it was mapped to [0x%llx 0x%llx), %p",
                   (unsigned long long)gpa,
                   (unsigned long long)gpa + size,
                   hva,
                   (unsigned long long)mem->start,
                   (unsigned long long)mem->start + mem->size,
                   mem->mem);
        abort();
    }

    mem = hvf_next_free_slot();

    if (mem->size) {
        error_report("no free slots");
        abort();
    }

    mem->mem = (uint8_t *)hva;
    mem->start = gpa;
    mem->size = size;

    int res = __hvf_set_memory_with_flags_locked(mem, (hv_memory_flags_t)flags);

    pthread_rwlock_unlock(&mem_lock);
    return res;
}

int hvf_unmap_safe(uint64_t gpa, uint64_t size)
{
    DPRINTF("%s: gpa: [0x%llx 0x%llx]\n", __func__,
            (unsigned long long)gpa,
            (unsigned long long)gpa + size);
    pthread_rwlock_wrlock(&mem_lock);

    hvf_slot *mem;
    int res = 0;
    mem = hvf_find_overlap_slot(gpa, size);

    if (mem &&
        (mem->start != gpa ||
         mem->size != size)) {

        pthread_rwlock_unlock(&mem_lock);

        error_report("tried to unmap [0x%llx 0x%llx) but partially overlapping "
                   "[0x%llx 0x%llx), %p was encountered",
                   gpa, gpa + size,
                   mem->start, mem->start + mem->size, mem->mem);
        abort();
    } else if (mem) {
        mem->size = 0;
        res = __hvf_set_memory_with_flags_locked(mem, 0);
    } else {
        /* fall through, allow res to be 0 still if slot was not found. */
    }

    pthread_rwlock_unlock(&mem_lock);
    return res;
}

int hvf_protect_safe(uint64_t gpa, uint64_t size, uint64_t flags)
{
    pthread_rwlock_wrlock(&mem_lock);
    int res = hv_vm_protect(gpa, size, flags);
    pthread_rwlock_unlock(&mem_lock);
    return res;
}

int hvf_remap_safe(void *hva, uint64_t gpa, uint64_t size, uint64_t flags)
{
    pthread_rwlock_wrlock(&mem_lock);
    int res = hv_vm_unmap(gpa, size);
    assert_hvf_ok(res);
    res = hv_vm_map(hva, gpa, size, flags);
    assert_hvf_ok(res);
    pthread_rwlock_unlock(&mem_lock);
    return res;
}

/**
 * API for adding and removing mappings of guest RAM and host addrs.
 * Implementation depends on the hypervisor.
 */
static hv_memory_flags_t user_backed_flags_to_hvf_flags(int flags)
{
    hv_memory_flags_t hvf_flags = 0;
    if (flags & USER_BACKED_RAM_FLAGS_READ) {
        hvf_flags |= HV_MEMORY_READ;
    }
    if (flags & USER_BACKED_RAM_FLAGS_WRITE) {
        hvf_flags |= HV_MEMORY_WRITE;
    }
    if (flags & USER_BACKED_RAM_FLAGS_EXEC) {
        hvf_flags |= HV_MEMORY_EXEC;
    }
    return hvf_flags;
}

static void hvf_user_backed_ram_map(uint64_t gpa,
                                    void *hva,
                                    uint64_t size,
                                    int flags)
{
    hvf_map_safe(hva, gpa, size, user_backed_flags_to_hvf_flags(flags));
}

static void hvf_user_backed_ram_unmap(uint64_t gpa, uint64_t size)
{
    hvf_unmap_safe(gpa, size);
}

static int __hvf_set_memory(hvf_slot *slot, hv_memory_flags_t flags)
{
    pthread_rwlock_wrlock(&mem_lock);
    int res = __hvf_set_memory_with_flags_locked(slot, flags);
    pthread_rwlock_unlock(&mem_lock);
    return res;
}

static int __hvf_set_memory_with_flags_locked(hvf_slot *slot,
                                              hv_memory_flags_t flags)
{
    struct mac_slot *macslot;

    macslot = &mac_slots[slot->slot_id];

    if (macslot->present) {
        if (macslot->size != slot->size) {
            macslot->present = 0;
            DPRINTF("%s: hv_vm_unmap for gpa [0x%llx 0x%llx]\n", __func__,
                    (unsigned long long)macslot->gpa_start,
                    (unsigned long long)(macslot->gpa_start + macslot->size));
            int unmapres = hv_vm_unmap(macslot->gpa_start, macslot->size);
            assert_hvf_ok(unmapres);
        }
    }

    if (!slot->size) {
        return 0;
    }

    macslot->present = 1;
    macslot->gpa_start = slot->start;
    macslot->size = slot->size;
    macslot->hva = slot->mem;
    DPRINTF("%s: hv_vm_map for hva 0x%llx gpa [0x%llx 0x%llx]\n", __func__,
            (unsigned long long)(slot->mem),
            (unsigned long long)macslot->gpa_start,
            (unsigned long long)(macslot->gpa_start + macslot->size));
    int mapres = (hv_vm_map(slot->mem, slot->start, slot->size, flags));
    assert_hvf_ok(mapres);
    return 0;
}

static void hvf_set_phys_mem(MemoryRegionSection *section, bool add)
{
    hvf_slot *mem;
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    hv_memory_flags_t flags;
    uint64_t page_size = qemu_real_host_page_size();

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return;
        } else if (!memory_region_is_romd(area)) {
            /*
            * If the memory device is not in romd_mode, then we actually want
            * to remove the hvf memory slot so all accesses will trap.
            */
            add = false;
        }
    }
    if (memory_region_is_user_backed(area)) {
        return;
    }

    if (!QEMU_IS_ALIGNED(int128_get64(section->size), page_size) ||
        !QEMU_IS_ALIGNED(section->offset_within_address_space, page_size)) {
        /* Not page aligned, so we can not map as RAM */
        add = false;
    }

    mem = hvf_find_overlap_slot(
            section->offset_within_address_space,
            int128_get64(section->size));

    if (mem && add) {
        if (mem->size == int128_get64(section->size) &&
            mem->start == section->offset_within_address_space &&
            mem->mem == (memory_region_get_ram_ptr(area) +
            section->offset_within_region)) {
            return; /* Same region was attempted to register, go away. */
        }
    }

    /* Region needs to be reset. set the size to 0 and remap it. */
    if (mem) {
        mem->size = 0;
        if (__hvf_set_memory(mem, 0)) {
            error_report("Failed to reset overlapping slot");
            abort();
        }
    }

    if (!add) {
        return;
    }

    if (area->readonly ||
        (!memory_region_is_ram(area) && memory_region_is_romd(area))) {
        flags = HV_MEMORY_READ | HV_MEMORY_EXEC;
    } else {
        flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
    }

    /* Now make a new slot. */

    mem = hvf_next_free_slot();

    if (!mem) {
        error_report("No free slots");
        abort();
    }

    mem->size = int128_get64(section->size);
    mem->mem = memory_region_get_ram_ptr(area) + section->offset_within_region;
    mem->start = section->offset_within_address_space;

    if (__hvf_set_memory(mem, flags)) {
        error_report("error regsitering new memory slot");
        abort();
    }
}

static void do_hvf_cpu_synchronize_state(CPUState *cpu, run_on_cpu_data arg)
{
    if (!cpu->vcpu_dirty) {
        hvf_get_registers(cpu);
        cpu->vcpu_dirty = true;
    }
}

static void hvf_cpu_synchronize_state(CPUState *cpu)
{
    if (!cpu->vcpu_dirty) {
        run_on_cpu(cpu, do_hvf_cpu_synchronize_state, RUN_ON_CPU_NULL);
    }
}

static void do_hvf_cpu_synchronize_set_dirty(CPUState *cpu,
                                             run_on_cpu_data arg)
{
    /* QEMU state is the reference, push it to HVF now and on next entry */
    cpu->vcpu_dirty = true;
}

static void hvf_cpu_synchronize_post_reset(CPUState *cpu)
{
    run_on_cpu(cpu, do_hvf_cpu_synchronize_set_dirty, RUN_ON_CPU_NULL);
}

static void hvf_cpu_synchronize_post_init(CPUState *cpu)
{
    run_on_cpu(cpu, do_hvf_cpu_synchronize_set_dirty, RUN_ON_CPU_NULL);
}

static void hvf_cpu_synchronize_pre_loadvm(CPUState *cpu)
{
    run_on_cpu(cpu, do_hvf_cpu_synchronize_set_dirty, RUN_ON_CPU_NULL);
}

static void hvf_set_dirty_tracking(MemoryRegionSection *section, bool on)
{
    hvf_slot *slot;

    slot = hvf_find_overlap_slot(
            section->offset_within_address_space,
            int128_get64(section->size));

    /* protect region against writes; begin tracking it */
    if (on) {
        slot->flags |= HVF_SLOT_LOG;
        hv_vm_protect((uintptr_t)slot->start, (size_t)slot->size,
                      HV_MEMORY_READ | HV_MEMORY_EXEC);
    /* stop tracking region*/
    } else {
        slot->flags &= ~HVF_SLOT_LOG;
        hv_vm_protect((uintptr_t)slot->start, (size_t)slot->size,
                      HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    }
}

static void hvf_log_start(MemoryListener *listener,
                          MemoryRegionSection *section, int old, int new)
{
    if (old != 0) {
        return;
    }

    hvf_set_dirty_tracking(section, 1);
}

static void hvf_log_stop(MemoryListener *listener,
                         MemoryRegionSection *section, int old, int new)
{
    if (new != 0) {
        return;
    }

    hvf_set_dirty_tracking(section, 0);
}

static void hvf_log_sync(MemoryListener *listener,
                         MemoryRegionSection *section)
{
    /*
     * sync of dirty pages is handled elsewhere; just make sure we keep
     * tracking the region.
     */
    hvf_set_dirty_tracking(section, 1);
}

static void hvf_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, true);
}

static void hvf_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, false);
}

static MemoryListener hvf_memory_listener = {
    .name = "hvf",
    .priority = 10,
    .region_add = hvf_region_add,
    .region_del = hvf_region_del,
    .log_start = hvf_log_start,
    .log_stop = hvf_log_stop,
    .log_sync = hvf_log_sync,
};

static void dummy_signal(int sig)
{
}

bool hvf_allowed;

static int hvf_accel_init(MachineState *ms)
{
    hv_return_t ret;
    HVFState *s = HVF_STATE(ms->accelerator);

    ret = hvf_arch_vm_create(s);
    assert_hvf_ok(ret);

    hvf_state = s;
    memory_listener_register(&hvf_memory_listener, &address_space_memory);
    qemu_set_user_backed_mapping_funcs(
        hvf_user_backed_ram_map,
        hvf_user_backed_ram_unmap);

    return hvf_arch_init();
}

#if defined(CONFIG_HVF_PRIVATE) && defined(__aarch64__)

static bool hvf_get_tso(Object *obj, Error **errp)
{
    HVFState *s = HVF_STATE(obj);
    return s->tso_mode;
}

static void hvf_set_tso(Object *obj, bool value, Error **errp)
{
    HVFState *s = HVF_STATE(obj);
    s->tso_mode = value;
}

#endif

static void hvf_accel_instance_init(Object *obj)
{
    int x;
    HVFState *s = HVF_STATE(obj);

    s->num_slots = ARRAY_SIZE(s->slots);
    for (x = 0; x < s->num_slots; ++x) {
        s->slots[x].size = 0;
        s->slots[x].slot_id = x;
    }
}

static void hvf_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "HVF";
    ac->init_machine = hvf_accel_init;
    ac->allowed = &hvf_allowed;

#if defined(CONFIG_HVF_PRIVATE) && defined(__aarch64__)
    object_class_property_add_bool(oc, "tso",
        hvf_get_tso, hvf_set_tso);
    object_class_property_set_description(oc, "tso",
        "Set on/off to enable/disable total store ordering mode");
#endif
}

static const TypeInfo hvf_accel_type = {
    .name = TYPE_HVF_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = hvf_accel_instance_init,
    .class_init = hvf_accel_class_init,
    .instance_size = sizeof(HVFState),
};

static void hvf_type_init(void)
{
    type_register_static(&hvf_accel_type);
}

type_init(hvf_type_init);

static void hvf_vcpu_destroy(CPUState *cpu)
{
    hv_return_t ret = hv_vcpu_destroy(cpu->hvf->fd);
    assert_hvf_ok(ret);

    hvf_arch_vcpu_destroy(cpu);
    g_free(cpu->hvf);
    cpu->hvf = NULL;
}

static int hvf_init_vcpu(CPUState *cpu)
{
    int r;

    cpu->hvf = g_malloc0(sizeof(*cpu->hvf));

    /* init cpu signals */
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = dummy_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &cpu->hvf->unblock_ipi_mask);
    sigdelset(&cpu->hvf->unblock_ipi_mask, SIG_IPI);

#ifdef __aarch64__
    r = hv_vcpu_create(&cpu->hvf->fd, (hv_vcpu_exit_t **)&cpu->hvf->exit, NULL);
#else
    r = hv_vcpu_create((hv_vcpuid_t *)&cpu->hvf->fd, HV_VCPU_DEFAULT);
#endif
    cpu->vcpu_dirty = 1;
    assert_hvf_ok(r);

    return hvf_arch_init_vcpu(cpu);
}

/*
 * The HVF-specific vCPU thread function. This one should only run when the host
 * CPU supports the VMX "unrestricted guest" feature.
 */
static void *hvf_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    int r;

    assert(hvf_enabled());

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);

    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;
    current_cpu = cpu;

    hvf_init_vcpu(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        if (cpu_can_run(cpu)) {
            r = hvf_vcpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    hvf_vcpu_destroy(cpu);
    cpu_thread_signal_destroyed(cpu);
    qemu_mutex_unlock_iothread();
    rcu_unregister_thread();
    return NULL;
}

static void hvf_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    /*
     * HVF currently does not support TCG, and only runs in
     * unrestricted-guest mode.
     */
    assert(hvf_enabled());

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);

    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/HVF",
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, hvf_cpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
}

static void hvf_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = hvf_start_vcpu_thread;
    ops->kick_vcpu_thread = hvf_kick_vcpu_thread;

    ops->synchronize_post_reset = hvf_cpu_synchronize_post_reset;
    ops->synchronize_post_init = hvf_cpu_synchronize_post_init;
    ops->synchronize_state = hvf_cpu_synchronize_state;
    ops->synchronize_pre_loadvm = hvf_cpu_synchronize_pre_loadvm;
};
static const TypeInfo hvf_accel_ops_type = {
    .name = ACCEL_OPS_NAME("hvf"),

    .parent = TYPE_ACCEL_OPS,
    .class_init = hvf_accel_ops_class_init,
    .abstract = true,
};
static void hvf_accel_ops_register_types(void)
{
    type_register_static(&hvf_accel_ops_type);
}
type_init(hvf_accel_ops_register_types);
