#ifndef EXEC_MEMORY_REMAH_H_INCLUDED
#define EXEC_MEMORY_REMAH_H_INCLUDED

#include <stdint.h>

/*
 * API for adding and removing mappings of guest RAM and host addrs.
 * Implementation depends on the hypervisor.
 */
#define USER_BACKED_RAM_FLAGS_NONE 0x0
#define USER_BACKED_RAM_FLAGS_READ 0x1
#define USER_BACKED_RAM_FLAGS_WRITE 0x2
#define USER_BACKED_RAM_FLAGS_EXEC 0x4
void qemu_user_backed_ram_map(uint64_t gpa, void* hva, uint64_t size, int flags);
void qemu_user_backed_ram_unmap(uint64_t gpa, uint64_t size);

#endif  /* EXEC_MEMORY_REMAH_H_INCLUDED */
