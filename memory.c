/*
 * RAM API
 *
 *  Copyright Red Hat, Inc. 2011
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include "memory.h"
#include "range.h"

typedef struct RamSlot {
    target_phys_addr_t start_addr;
    ram_addr_t size;
    ram_addr_t offset;
    QLIST_ENTRY(RamSlot) next;
} RamSlot;

static QLIST_HEAD(ram_slot_list, RamSlot) ram_slot_list =
    QLIST_HEAD_INITIALIZER(ram_slot_list);

static RamSlot *ram_find_slot(target_phys_addr_t start_addr, ram_addr_t size)
{
    RamSlot *slot;

    QLIST_FOREACH(slot, &ram_slot_list, next) {
        if (slot->start_addr == start_addr && slot->size == size) {
            return slot;
        }

        if (ranges_overlap(start_addr, size, slot->start_addr, slot->size)) {
            hw_error("Ram range overlaps existing slot\n");
        }
    }

    return NULL;
}

int ram_register(target_phys_addr_t start_addr, ram_addr_t size,
                 ram_addr_t phys_offset)
{
    RamSlot *slot;

    if (!size) {
        return -EINVAL;
    }

    assert(!ram_find_slot(start_addr, size));

    slot = qemu_malloc(sizeof(RamSlot));

    slot->start_addr = start_addr;
    slot->size = size;
    slot->offset = phys_offset;

    QLIST_INSERT_HEAD(&ram_slot_list, slot, next);

    cpu_register_physical_memory(slot->start_addr, slot->size, slot->offset);

    return 0;
}

void ram_unregister(target_phys_addr_t start_addr, ram_addr_t size)
{
    RamSlot *slot;

    if (!size) {
        return;
    }

    slot = ram_find_slot(start_addr, size);
    assert(slot != NULL);

    QLIST_REMOVE(slot, next);
    qemu_free(slot);
    cpu_register_physical_memory(start_addr, size, IO_MEM_UNASSIGNED);
}

int ram_for_each_slot(void *opaque, ram_for_each_slot_fn fn)
{
    RamSlot *slot;

    QLIST_FOREACH(slot, &ram_slot_list, next) {
        int ret = fn(opaque, slot->start_addr, slot->size, slot->offset);
        if (ret) {
            return ret;
        }
    }
    return 0;
}
