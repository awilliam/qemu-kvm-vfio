#ifndef QEMU_MEMORY_H
#define QEMU_MEMORY_H
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

#include "qemu-common.h"
#include "cpu-common.h"

typedef int (*ram_for_each_slot_fn)(void *opaque,
                                    target_phys_addr_t start_addr,
                                    ram_addr_t size,
                                    ram_addr_t phys_offset);

/**
 * ram_register() : Register a region of guest physical memory
 *
 * The new region must not overlap an existing region.
 */
int ram_register(target_phys_addr_t start_addr, ram_addr_t size,
                 ram_addr_t phys_offset);

/**
 * ram_unregister() : Unregister a region of guest physical memory
 */
void ram_unregister(target_phys_addr_t start_addr, ram_addr_t size);

/**
 * ram_for_each_slot() : Call fn() on each registered region
 *
 * Stop on non-zero return from fn().
 */
int ram_for_each_slot(void *opaque, ram_for_each_slot_fn fn);

#endif /* QEMU_MEMORY_H */
