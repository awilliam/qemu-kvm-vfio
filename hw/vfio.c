/*
 * vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2011
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"
#include "event_notifier.h"
#include "hw.h"
#include "kvm.h"
#include "memory.h"
#include "monitor.h"
#include "msi.h"
#include "msix.h"
#include "notify.h"
#include "pc.h"
#include "qemu-error.h"
#include "range.h"
#include "vfio.h"
#include <pci/header.h>
#include <pci/types.h>
#include <linux/types.h>
#include "linux-vfio.h"

//#define DEBUG_VFIO
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { printf("vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

/* TODO: msix.h should define these */
#define MSIX_CAP_LENGTH 12
#define MSIX_PAGE_SIZE 0x1000

/* XXX: on qemu-kvm.git we have msix/intx notifiers and irqfds.  With these
 * we can allow interrupts to bypass userspace.  There's no good #define to
 * figure out when these are present, so we toggle on the device assignment
 * ifdef even though it has no relation to the bits we're looking for. */
#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
#define QEMU_KVM_BUILD
#endif

static void vfio_disable_interrupts(VFIODevice *vdev);
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len);
static void vfio_pci_write_config(PCIDevice *pdev, uint32_t addr,
                                  uint32_t val, int len);
/*
 * Generic
 */
static uint8_t pci_find_cap_offset(PCIDevice *pdev, uint8_t cap)
{
    int id;
    int max_cap = 48;
    int pos = PCI_CAPABILITY_LIST;
    int status;

    status = pdev->config[PCI_STATUS];
    if ((status & PCI_STATUS_CAP_LIST) == 0) {
        return 0;
    }

    while (max_cap--) {
        pos = pdev->config[pos];
        if (pos < 0x40) {
            break;
        }

        pos &= ~3;
        id = pdev->config[pos + PCI_CAP_LIST_ID];

        if (id == 0xff) {
            break;
        }
        if (id == cap) {
            return pos;
        }

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

static int parse_hostaddr(DeviceState *qdev, Property *prop, const char *str)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(qdev, prop);
    const char *p = str;
    int n, seg, bus, dev, func;
    char field[5];

    if (sscanf(p, "%4[^:]%n", field, &n) != 1 || p[n] != ':') {
        return -EINVAL;
    }

    seg = strtol(field, NULL, 16);
    p += n + 1;

    if (sscanf(p, "%4[^:]%n", field, &n) != 1) {
        return -EINVAL;
    }

    if (p[n] == ':') {
        bus = strtol(field, NULL, 16);
        p += n + 1;
    } else {
        bus = seg;
        seg = 0;
    }

    if (sscanf(p, "%4[^.]%n", field, &n) != 1 || p[n] != '.') {
        return -EINVAL;
    }

    dev = strtol(field, NULL, 16);
    p += n + 1;

    if (!qemu_isdigit(*p)) {
        return -EINVAL;
    }

    func = *p - '0';

    ptr->seg = seg;
    ptr->bus = bus;
    ptr->dev = dev;
    ptr->func = func;
    return 0;
}

static int print_hostaddr(DeviceState *qdev, Property *prop,
                          char *dest, size_t len)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(qdev, prop);

    return snprintf(dest, len, "%04x:%02x:%02x.%x",
                    ptr->seg, ptr->bus, ptr->dev, ptr->func);
}

/*
 * INTx
 */
static inline void vfio_unmask_intx(VFIODevice *vdev)
{
    ioctl(vdev->vfiofd, VFIO_IRQ_EOI);
}

static void vfio_intx_interrupt(void *opaque)
{
    VFIODevice *vdev = opaque;

    if (!event_notifier_test_and_clear(&vdev->intx.interrupt)) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) Pin %c\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func,
            'A' + vdev->intx.pin);

    vdev->intx.pending = true;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 1);
}

static void vfio_eoi(Notifier *notify)
{
    VFIODevice *vdev = container_of(notify, VFIODevice, intx.eoi);

    if (!vdev->intx.pending) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) EOI\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    vdev->intx.pending = false;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 0);
    vfio_unmask_intx(vdev);
}

static void vfio_update_irq(Notifier *notify)
{
    VFIODevice *vdev = container_of(notify, VFIODevice, intx.update_irq);
    int irq = pci_get_irq(&vdev->pdev, vdev->intx.pin);

    if (irq == vdev->intx.irq) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) IRQ moved %d -> %d\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->intx.irq, irq);

    ioapic_remove_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    vdev->intx.irq = irq;

    if (irq < 0) {
        fprintf(stderr, "vfio: Error - INTx moved to IRQ %d\n", irq);
        return;
    }

    ioapic_add_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    /* Re-enable the interrupt in cased we missed an EOI */
    vfio_eoi(&vdev->intx.eoi);
}

static int vfio_enable_intx(VFIODevice *vdev)
{
    int fd;
    uint8_t pin = vfio_pci_read_config(&vdev->pdev, PCI_INTERRUPT_PIN, 1);

    if (!pin) {
        return 0;
    }

    vfio_disable_interrupts(vdev);

    vdev->intx.pin = pin - 1; /* Pin A (1) -> irq[0] */
    vdev->intx.irq = pci_get_irq(&vdev->pdev, vdev->intx.pin);
    vdev->intx.eoi.notify = vfio_eoi;
    ioapic_add_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    vdev->intx.update_irq.notify = vfio_update_irq;
    pci_add_irq_update_notifier(&vdev->pdev, &vdev->intx.update_irq);

    if (event_notifier_init(&vdev->intx.interrupt, 0)) {
        fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        return -1;
    }

    fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd, vfio_intx_interrupt, NULL, vdev);

    if (ioctl(vdev->vfiofd, VFIO_EVENTFD_IRQ, &fd)) {
        fprintf(stderr, "vfio: Error: Failed to setup INTx fd %s\n",
                strerror(errno));
        return -1;
    }

    vdev->interrupt = INT_INTx;

    vfio_unmask_intx(vdev);

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    return 0;
}

static void vfio_disable_intx(VFIODevice *vdev)
{
    int fd = -1;

    if (vdev->interrupt != INT_INTx) {
        return;
    }

    ioctl(vdev->vfiofd, VFIO_EVENTFD_IRQ, &fd);

    pci_remove_irq_update_notifier(&vdev->pdev, &vdev->intx.update_irq);
    ioapic_remove_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd, NULL, NULL, vdev);
    event_notifier_cleanup(&vdev->intx.interrupt);

    vdev->interrupt = INT_NONE;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);
}

/*
 * MSI-X
 */
static void vfio_msix_interrupt(void *opaque)
{
    MSIVector *vec = opaque;
    VFIODevice *vdev = vec->vdev;

    if (!event_notifier_test_and_clear(&vec->interrupt)) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func, vec->vector);

    msix_notify(&vdev->pdev, vec->vector);
}

#ifdef QEMU_KVM_BUILD
/* When a vector is masked, we disable the irqfd, forcing the interrupt
 * through qemu userspace.  We can then filter masked vectors in msix_notify. */
static int vfio_msix_mask_notify(PCIDevice *pdev, unsigned vector, int masked)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    int fd, ret;

    fd = event_notifier_get_fd(&vdev->msi_vectors[vector].interrupt);
    ret = kvm_set_irqfd(pdev->msix_irq_entries[vector].gsi, fd, !masked);
    if (ret == -ENOSYS) {
        return 0; /* w/o irqfd, interrupts pass through qemu anyway */
    } else if (ret < 0) {
        fprintf(stderr, "vfio: Error - irqfd setup failed\n");
        return ret;
    }

    if (masked) {
        qemu_set_fd_handler(fd, vfio_msix_interrupt, NULL,
                            &vdev->msi_vectors[vector]);
    } else {
        qemu_set_fd_handler(fd, NULL, NULL, NULL);
    }

    return ret;
}
#endif

static void vfio_enable_msix(VFIODevice *vdev)
{
    int i, *fds;

    vfio_disable_interrupts(vdev);

    vdev->nr_vectors = vdev->pdev.msix_entries_nr;
    vdev->msi_vectors = qemu_malloc(vdev->nr_vectors * sizeof(MSIVector));

    fds = qemu_malloc((vdev->nr_vectors + 1) * sizeof(int));
    fds[0] = vdev->nr_vectors;

    for (i = 0; i < vdev->nr_vectors; i++) {
        vdev->msi_vectors[i].vdev = vdev;
        vdev->msi_vectors[i].vector = i;

        if (event_notifier_init(&vdev->msi_vectors[i].interrupt, 0)) {
            fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        }

        fds[i + 1] = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
        qemu_set_fd_handler(fds[i + 1], vfio_msix_interrupt, NULL,
                            &vdev->msi_vectors[i]);

        if (msix_vector_use(&vdev->pdev, i) < 0) {
            fprintf(stderr, "vfio: Error msix_vector_use\n");
        }
    }

    if (ioctl(vdev->vfiofd, VFIO_EVENTFDS_MSIX, fds)) {
        fprintf(stderr, "vfio: Error: Failed to setup MSIX fds %s\n",
                strerror(errno));
        qemu_free(fds);
        return;
    }

    vdev->interrupt = INT_MSIX;

    qemu_free(fds);

#ifdef QEMU_KVM_BUILD
    if (msix_set_mask_notifier(&vdev->pdev, vfio_msix_mask_notify)) {
        fprintf(stderr, "vfio: Error msix_set_mask_notifier\n");
    }
#endif

    DPRINTF("%s(%04x:%02x:%02x.%x) Enabled %d vectors\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->nr_vectors);
}

static void vfio_disable_msix(VFIODevice *vdev)
{
    int i, vectors = 0;

    if (vdev->interrupt != INT_MSIX) {
        return;
    }

    ioctl(vdev->vfiofd, VFIO_EVENTFDS_MSIX, &vectors);

#ifdef QEMU_KVM_BUILD
    if (msix_unset_mask_notifier(&vdev->pdev)) {
        fprintf(stderr, "vfio: Error msix_unset_mask_notifier\n");
    }
#endif

    for (i = 0; i < vdev->nr_vectors; i++) {
        int fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);

        msix_vector_unuse(&vdev->pdev, i);

        qemu_set_fd_handler(fd, NULL, NULL, NULL);
        event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
    }

    qemu_free(vdev->msi_vectors);
    vdev->nr_vectors = 0;
    vdev->interrupt = INT_NONE;
    vfio_enable_intx(vdev);

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);
}

/*
 * MSI
 */
static void vfio_msi_interrupt(void *opaque)
{
    MSIVector *vec = opaque;
    VFIODevice *vdev = vec->vdev;

    if (!event_notifier_test_and_clear(&vec->interrupt)) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func, vec->vector);

    msi_notify(&vdev->pdev, vec->vector);
}

static void vfio_enable_msi(VFIODevice *vdev)
{
    int i, *fds;

    vfio_disable_interrupts(vdev);

    vdev->nr_vectors = msi_nr_vectors_allocated(&vdev->pdev);
    vdev->msi_vectors = qemu_malloc(vdev->nr_vectors * sizeof(MSIVector));

    fds = qemu_malloc((vdev->nr_vectors + 1) * sizeof(int));
    fds[0] = vdev->nr_vectors;

    for (i = 0; i < vdev->nr_vectors; i++) {
        vdev->msi_vectors[i].vdev = vdev;
        vdev->msi_vectors[i].vector = i;

        if (event_notifier_init(&vdev->msi_vectors[i].interrupt, 0)) {
            fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        }

        fds[i + 1] = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
        qemu_set_fd_handler(fds[i + 1], vfio_msi_interrupt, NULL,
                            &vdev->msi_vectors[i]);
    }

    if (ioctl(vdev->vfiofd, VFIO_EVENTFDS_MSI, fds)) {
        fprintf(stderr, "vfio: Error: Failed to setup MSI fds %s\n",
                strerror(errno));
        qemu_free(fds);
        return;
    }

    vdev->interrupt = INT_MSI;

    qemu_free(fds);

    DPRINTF("%s(%04x:%02x:%02x.%x) Enabled %d vectors\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->nr_vectors);
}

static void vfio_disable_msi(VFIODevice *vdev)
{
    int i, vectors = 0;

    if (vdev->interrupt != INT_MSI) {
        return;
    }

    ioctl(vdev->vfiofd, VFIO_EVENTFDS_MSI, &vectors);

    for (i = 0; i < vdev->nr_vectors; i++) {
        int fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
        qemu_set_fd_handler(fd, NULL, NULL, NULL);
        event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
    }

    qemu_free(vdev->msi_vectors);
    vdev->nr_vectors = 0;
    vdev->interrupt = INT_NONE;
    vfio_enable_intx(vdev);

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);
}

/*
 * IO Port/MMIO
 */
static void vfio_resource_write(PCIResource *res, uint32_t addr,
                                uint32_t val, int len)
{
    size_t offset = vfio_pci_space_to_offset(VFIO_PCI_BAR0_RESOURCE + res->bar);

    if (pwrite(res->vfiofd, &val, len, offset + addr) != len) {
        fprintf(stderr, "%s(,0x%x, 0x%x, %d) failed: %s\n",
                __FUNCTION__, addr, val, len, strerror(errno));
    }
    DPRINTF("%s(BAR%d+0x%x, 0x%x, %d)\n", __FUNCTION__, res->bar,
            addr, val, len);
}

static void vfio_resource_writeb(void *opaque, target_phys_addr_t addr,
                                 uint32_t val)
{
    vfio_resource_write(opaque, addr, val, 1);
}

static void vfio_resource_writew(void *opaque, target_phys_addr_t addr,
                                 uint32_t val)
{
    vfio_resource_write(opaque, addr, val, 2);
}

static void vfio_resource_writel(void *opaque, target_phys_addr_t addr,
                                 uint32_t val)
{
    vfio_resource_write(opaque, addr, val, 4);
}

static CPUWriteMemoryFunc * const vfio_resource_writes[] = {
    &vfio_resource_writeb,
    &vfio_resource_writew,
    &vfio_resource_writel
};

static void vfio_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIResource *res = opaque;
    vfio_resource_write(res, addr - res->e_phys, val, 1);
}

static void vfio_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCIResource *res = opaque;
    vfio_resource_write(res, addr - res->e_phys, val, 2);
}

static void vfio_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    PCIResource *res = opaque;
    vfio_resource_write(res, addr - res->e_phys, val, 4);
}

static uint32_t vfio_resource_read(PCIResource *res, uint32_t addr, int len)
{
    size_t offset = vfio_pci_space_to_offset(VFIO_PCI_BAR0_RESOURCE + res->bar);
    uint32_t val;

    if (pread(res->vfiofd, &val, len, offset + addr) != len) {
        fprintf(stderr, "%s(,0x%x, %d) failed: %s\n",
                __FUNCTION__, addr, len, strerror(errno));
        return 0xffffffffU;
    }
    DPRINTF("%s(BAR%d+0x%x, %d) = 0x%x\n", __FUNCTION__, res->bar,
            addr, len, val);
    return val;
}

static uint32_t vfio_resource_readb(void *opaque, target_phys_addr_t addr)
{
    return vfio_resource_read(opaque, addr, 1) & 0xff;
}

static uint32_t vfio_resource_readw(void *opaque, target_phys_addr_t addr)
{
    return vfio_resource_read(opaque, addr, 2) & 0xffff;
}

static uint32_t vfio_resource_readl(void *opaque, target_phys_addr_t addr)
{
    return vfio_resource_read(opaque, addr, 4);
}

static CPUReadMemoryFunc * const vfio_resource_reads[] = {
    &vfio_resource_readb,
    &vfio_resource_readw,
    &vfio_resource_readl
};

static uint32_t vfio_ioport_readb(void *opaque, uint32_t addr)
{
    PCIResource *res = opaque;
    return vfio_resource_read(res, addr - res->e_phys, 1) & 0xff;
}

static uint32_t vfio_ioport_readw(void *opaque, uint32_t addr)
{
    PCIResource *res = opaque;
    return vfio_resource_read(res, addr - res->e_phys, 2) & 0xffff;
}

static uint32_t vfio_ioport_readl(void *opaque, uint32_t addr)
{
    PCIResource *res = opaque;
    return vfio_resource_read(res, addr - res->e_phys, 4);
}

static void vfio_ioport_map(PCIDevice *pdev, int bar,
                           pcibus_t e_phys, pcibus_t e_size, int type)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    PCIResource *res = &vdev->resources[bar];

    DPRINTF("%s(%04x:%02x:%02x.%x, %d, 0x%lx, 0x%lx, %d)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, bar, e_phys, e_size, type);

    res->e_phys = e_phys;
    res->e_size = e_size;

    register_ioport_write(e_phys, e_size, 1, vfio_ioport_writeb, res);
    register_ioport_write(e_phys, e_size, 2, vfio_ioport_writew, res);
    register_ioport_write(e_phys, e_size, 4, vfio_ioport_writel, res);
    register_ioport_read(e_phys, e_size, 1, vfio_ioport_readb, res);
    register_ioport_read(e_phys, e_size, 2, vfio_ioport_readw, res);
    register_ioport_read(e_phys, e_size, 4, vfio_ioport_readl, res);
}

static void vfio_iomem_map(PCIDevice *pdev, int bar,
                           pcibus_t e_phys, pcibus_t e_size, int type)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    PCIResource *res = &vdev->resources[bar];

    DPRINTF("%s(%04x:%02x:%02x.%x, %d, 0x%lx, 0x%lx, %d)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, bar, e_phys, e_size, type);

    res->e_phys = e_phys;
    res->e_size = e_size;

    if (res->msix) {
        if (res->msix_offset > 0) {
            cpu_register_physical_memory(e_phys, res->msix_offset, res->slow ?
                                         res->io_mem : res->memory_index[0]);
        }

        DPRINTF("Overlaying MSI-X table page\n");
        msix_mmio_map(pdev, bar, e_phys, e_size, type);

        if (e_size > res->msix_offset + MSIX_PAGE_SIZE) {
            uint32_t offset = res->msix_offset + MSIX_PAGE_SIZE;
            e_phys += offset;
            e_size -= offset;
            cpu_register_physical_memory_offset(e_phys, e_size,
                            res->slow ? res->io_mem : res->memory_index[1],
                            res->slow ? offset : 0);
        }
    } else {
        cpu_register_physical_memory(e_phys, e_size, res->slow ?
                                     res->io_mem : res->memory_index[0]);
    }
}

/*
 * PCI config space
 */
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    uint32_t val = 0;

    if (ranges_overlap(addr, len, PCI_ROM_ADDRESS, 4) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
         ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSI &&
         ranges_overlap(addr, len, pdev->msi_cap, pdev->msi_cap_size))) {

        val = pci_default_read_config(pdev, addr, len);
    } else {
        if (pread(vdev->vfiofd, &val, len, VFIO_PCI_CONFIG_OFF + addr) != len) {
            fprintf(stderr, "%s(%04x:%02x:%02x.%x, 0x%x, 0x%x) failed: %s\n",
                    __FUNCTION__, vdev->host.seg, vdev->host.bus,
                    vdev->host.dev, vdev->host.func, addr, len,
                    strerror(errno));
            return -1;
        }
    }
    DPRINTF("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x) %x\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, len, val);
    return val;
}

static void vfio_pci_write_config(PCIDevice *pdev, uint32_t addr,
                                  uint32_t val, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    DPRINTF("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x, 0x%x)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, val, len);

    /* Write everything to VFIO, let it filter out what we can't write */
    if (pwrite(vdev->vfiofd, &val, len, VFIO_PCI_CONFIG_OFF + addr) != len) {
        fprintf(stderr, "%s(%04x:%02x:%02x.%x, 0x%x, 0x%x, 0x%x) failed: %s\n",
                __FUNCTION__, vdev->host.seg, vdev->host.bus, vdev->host.dev,
                vdev->host.func, addr, val, len, strerror(errno));
    }

    /* Write standard header bits to emulation */
    if (addr < 0x40) {
        pci_default_write_config(pdev, addr, val, len);
        return;
    }

    /* MSI/MSI-X Enabling/Disabling */
    if (pdev->cap_present & QEMU_PCI_CAP_MSI &&
        ranges_overlap(addr, len, pdev->msi_cap, pdev->msi_cap_size)) {
        int is_enabled, was_enabled = msi_enabled(pdev);

        pci_default_write_config(pdev, addr, val, len);
        msi_write_config(pdev, addr, val, len);

        is_enabled = msi_enabled(pdev);

        if (!was_enabled && is_enabled) {
            vfio_enable_msi(vdev);
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msi(vdev);
        }
    }

    if (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
        ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) {
        int is_enabled, was_enabled = msix_enabled(pdev);

        pci_default_write_config(pdev, addr, val, len);
        msix_write_config(pdev, addr, val, len);

        is_enabled = msix_enabled(pdev);

        if (!was_enabled && is_enabled) {
            vfio_enable_msix(vdev);
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msix(vdev);
        }
    }
}

/*
 * DMA
 */
static int vfio_dma_map(void *opaque, target_phys_addr_t start_addr,
                        ram_addr_t size, ram_addr_t phys_offset)
{
    VFIODevice *vdev = opaque;
    struct vfio_dma_map dma_map;
    int ret;

    dma_map.vaddr = (uint64_t)qemu_get_ram_ptr(phys_offset);
    dma_map.dmaaddr = start_addr;
    dma_map.flags = VFIO_FLAG_WRITE;

    /* VFIO has an odd requirement that size is less than 1G.  For
     * convenience, we'll cut this in half to maintain alignments and
     * page sizes.  TODO: error/handle non-host page aligned regions */
    while (size) {
        dma_map.size = MIN(size, VFIO_MAX_MAP_SIZE >> 1);

        if ((ret =  ioctl(vdev->vfiofd, VFIO_DMA_MAP_IOVA, &dma_map))) {
            return ret;
        }

        size -= dma_map.size;
        dma_map.vaddr += dma_map.size;
        dma_map.dmaaddr += dma_map.size;
    }

    return 0;
}

static int vfio_dma_unmap(void *opaque, target_phys_addr_t start_addr,
                          ram_addr_t size, ram_addr_t phys_offset)
{
    VFIODevice *vdev = opaque;
    struct vfio_dma_map dma_map;
    int ret;

    dma_map.vaddr = (uint64_t)qemu_get_ram_ptr(phys_offset);
    dma_map.dmaaddr = start_addr;
    dma_map.flags = VFIO_FLAG_WRITE;

    while (size) {
        dma_map.size = MIN(size, VFIO_MAX_MAP_SIZE >> 1);

        if ((ret =  ioctl(vdev->vfiofd, VFIO_DMA_UNMAP, &dma_map))) {
            return ret;
        }

        size -= dma_map.size;
        dma_map.vaddr += dma_map.size;
        dma_map.dmaaddr += dma_map.size;
    }

    return 0;
}

static int vfio_map_iommu(VFIODevice *vdev)
{
    return ram_for_each_slot(vdev, vfio_dma_map);
}

static int vfio_unmap_iommu(VFIODevice *vdev)
{
    return ram_for_each_slot(vdev, vfio_dma_unmap);
}

/*
 * Interrupt setup
 */
static void vfio_disable_interrupts(VFIODevice *vdev)
{
    switch (vdev->interrupt) {
    case INT_INTx:
        vfio_disable_intx(vdev);
        break;
    case INT_MSI:
        vfio_disable_msi(vdev);
        break;
    case INT_MSIX:
        vfio_disable_msix(vdev);
    }
}

static int vfio_setup_msi(VFIODevice *vdev)
{
    int pos;

    if ((pos = pci_find_cap_offset(&vdev->pdev, PCI_CAP_ID_MSI))) {
        uint16_t ctrl;
        bool msi_64bit, msi_maskbit;
        int entries;

        if (pread(vdev->vfiofd, &ctrl, sizeof(ctrl),
                  VFIO_PCI_CONFIG_OFF + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
            return -1;
        }

        msi_64bit = !!(ctrl & PCI_MSI_FLAGS_64BIT);
        msi_maskbit = !!(ctrl & PCI_MSI_FLAGS_MASKBIT);
        entries = 1 << ((ctrl & PCI_MSI_FLAGS_QMASK) >> 1);

        DPRINTF("%04x:%02x:%02x.%x PCI MSI CAP @0x%x\n", vdev->host.seg,
                vdev->host.bus, vdev->host.dev, vdev->host.func, pos);

        if (msi_init(&vdev->pdev, pos, entries, msi_64bit, msi_maskbit) < 0) {
            fprintf(stderr, "vfio: msi_init failed\n");
            return -1;
        }
    }

    if ((pos = pci_find_cap_offset(&vdev->pdev, PCI_CAP_ID_MSIX))) {
        uint16_t ctrl;
        uint32_t table, len, offset;
        int bar, entries;

        if (pread(vdev->vfiofd, &ctrl, sizeof(ctrl),
                  VFIO_PCI_CONFIG_OFF + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
            return -1;
        }

        if (pread(vdev->vfiofd, &table, sizeof(table), VFIO_PCI_CONFIG_OFF +
                  pos + PCI_MSIX_TABLE) != sizeof(table)) {
            return -1;
        }

        ctrl = le16_to_cpu(ctrl);
        table = le32_to_cpu(table);

        bar = table & PCI_MSIX_BIR;
        offset = table & ~PCI_MSIX_BIR;
        entries = (ctrl & PCI_MSIX_TABSIZE) + 1;

        vdev->resources[bar].msix = true;
        vdev->resources[bar].msix_offset = offset;

        DPRINTF("%04x:%02x:%02x.%x PCI MSI-X CAP @0x%x, BAR %d, offset 0x%x\n",
                vdev->host.seg, vdev->host.bus, vdev->host.dev,
                vdev->host.func, pos, bar, offset);

        len = table & PCI_MSIX_BIR;
        if (ioctl(vdev->vfiofd, VFIO_BAR_LEN, &len)) {
            fprintf(stderr, "vfio: VFIO_BAR_LEN failed for MSIX BAR\n");
            return -1;
        }

        if (msix_init(&vdev->pdev, entries, bar, len) < 0) {
            fprintf(stderr, "vfio: msix_init failed\n");
            return -1;
        }
    }
    return 0;
}

static void vfio_teardown_msi(VFIODevice *vdev)
{
    msi_uninit(&vdev->pdev);
    msix_uninit(&vdev->pdev);
}

/*
 * Resource setup
 */
static int vfio_setup_resources(VFIODevice *vdev)
{
    int i;

    for (i = 0; i < PCI_ROM_SLOT; i++) {
        uint32_t len, bar;
        PCIResource *res;
        uint8_t offset;
        int ret, space;

        res = &vdev->resources[i];
        res->vfiofd = vdev->vfiofd;
        res->bar = len = i;

        if (ioctl(vdev->vfiofd, VFIO_BAR_LEN, &len)) {
            fprintf(stderr, "vfio: VFIO_BAR_LEN failed for BAR %d\n", i);
            return -1;
        }
        if (!len) {
            continue;
        }

        offset = PCI_BASE_ADDRESS_0 + (4 * i);
        ret = pread(vdev->vfiofd, &bar, sizeof(bar),
                    VFIO_PCI_CONFIG_OFF + offset);
        if (ret != sizeof(bar)) {
            fprintf(stderr, "vfio: Failed to read BAR %d\n", i);
            return -1;
        }
        bar = le32_to_cpu(bar);
        space = bar & PCI_BASE_ADDRESS_SPACE;

        if (space == PCI_BASE_ADDRESS_SPACE_MEMORY && !(len & 0xfff)) {
            int off = VFIO_PCI_BAR0_RESOURCE + i;
            int flags = PROT_READ | PROT_WRITE;
            char name[32];

            res->mem = true;
            res->size = len;

            if (vdev->pdev.qdev.info->vmsd) {
                snprintf(name, sizeof(name), "%s.bar%d",
                         vdev->pdev.qdev.info->vmsd->name, i);
            } else {
                snprintf(name, sizeof(name), "%s.bar%d",
                         vdev->pdev.qdev.info->name, i);
            }

            if (res->msix) {
                if (res->msix_offset) {
                    char *c = &name[strlen(name)];

                    res->r_virtbase[0] = mmap(NULL, res->msix_offset, flags,
                                              MAP_SHARED, vdev->vfiofd,
                                              vfio_pci_space_to_offset(off));

                    if (res->r_virtbase[0] == MAP_FAILED) {
                        fprintf(stderr, "vfio: Failed to mmap BAR %d\n", i);
                        return -1;
                    }
                    strncat(name, ".0", sizeof(name));
                    res->memory_index[0] =
                        qemu_ram_alloc_from_ptr(&vdev->pdev.qdev,
                                                name, res->msix_offset,
                                                res->r_virtbase[0]);
                    *c = 0;
                }
                if (len > res->msix_offset + MSIX_PAGE_SIZE) {
                    char *c = &name[strlen(name)];

                    res->r_virtbase[1] = mmap(NULL,
                                        len - res->msix_offset - MSIX_PAGE_SIZE,
                                        flags, MAP_SHARED, vdev->vfiofd,
                                        vfio_pci_space_to_offset(off) +
                                        res->msix_offset + MSIX_PAGE_SIZE);

                    if (res->r_virtbase[1] == MAP_FAILED) {
                        fprintf(stderr, "vfio: Failed to mmap BAR %d\n", i);
                        return -1;
                    }
                    strncat(name, ".1", sizeof(name));
                    res->memory_index[1] =
                        qemu_ram_alloc_from_ptr(&vdev->pdev.qdev, name,
                                        len - MSIX_PAGE_SIZE - res->msix_offset,
                                        res->r_virtbase[1]);
                    *c = 0;
                }
            } else {
                res->r_virtbase[0] = mmap(NULL, len, flags, MAP_SHARED,
                                          vdev->vfiofd,
                                          vfio_pci_space_to_offset(off));

                if (res->r_virtbase[0] == MAP_FAILED) {
                    fprintf(stderr, "vfio: Failed to mmap BAR %d\n", i);
                    return -1;
                }
                res->memory_index[0] =
                    qemu_ram_alloc_from_ptr(&vdev->pdev.qdev,
                                            name, len, res->r_virtbase[0]);
            }

            pci_register_bar(&vdev->pdev, i, res->size,
                             bar & PCI_BASE_ADDRESS_MEM_PREFETCH ?
                             PCI_BASE_ADDRESS_MEM_PREFETCH :
                             PCI_BASE_ADDRESS_SPACE_MEMORY,
                             vfio_iomem_map);

            if (bar & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                i++;
            }
        } else if (space == PCI_BASE_ADDRESS_SPACE_MEMORY) {
            res->mem = true;
            res->size = len;
            res->slow = true;

            DPRINTF("%s(%04x:%02x:%02x.%x) Using slow mapping for BAR %d\n",
                    __FUNCTION__, vdev->host.seg, vdev->host.bus,
                    vdev->host.dev, vdev->host.func, i);

            res->io_mem = cpu_register_io_memory(vfio_resource_reads,
                                                 vfio_resource_writes,
                                                 res, DEVICE_NATIVE_ENDIAN);

            pci_register_bar(&vdev->pdev, i, res->size,
                             bar & PCI_BASE_ADDRESS_MEM_PREFETCH ?
                             PCI_BASE_ADDRESS_MEM_PREFETCH :
                             PCI_BASE_ADDRESS_SPACE_MEMORY,
                             vfio_iomem_map);

            if (bar & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                i++;
            }
        } else if (space == PCI_BASE_ADDRESS_SPACE_IO) {
            res->size = len;
            pci_register_bar(&vdev->pdev, i, res->size,
                             PCI_BASE_ADDRESS_SPACE_IO, vfio_ioport_map);
        }
        res->valid = true;
    }
    return 0;
}

static void vfio_unmap_resources(VFIODevice *vdev)
{
    int i;
    PCIResource *res = vdev->resources;

    for (i = 0; i < PCI_ROM_SLOT; i++, res++) {
        if (res->valid && res->mem) {
            if (res->msix) {
                if (res->msix_offset) {
                    cpu_register_physical_memory(res->e_phys, res->msix_offset,
                                                 IO_MEM_UNASSIGNED);
                    qemu_ram_free_from_ptr(res->memory_index[0]);
                    munmap(res->r_virtbase[0], res->msix_offset);
                }
                if (res->size > res->msix_offset + MSIX_PAGE_SIZE) {
                    cpu_register_physical_memory(res->e_phys + MSIX_PAGE_SIZE +
                                                 res->msix_offset,
                                                 res->e_size - MSIX_PAGE_SIZE -
                                                 res->msix_offset,
                                                 IO_MEM_UNASSIGNED);
                    qemu_ram_free_from_ptr(res->memory_index[1]);
                    munmap(res->r_virtbase[1],
                           res->size - MSIX_PAGE_SIZE - res->msix_offset);
                }
            } else {
                if (!res->slow) {
                    cpu_register_physical_memory(res->e_phys, res->e_size,
                                                 IO_MEM_UNASSIGNED);
                    qemu_ram_free_from_ptr(res->memory_index[0]);
                    munmap(res->r_virtbase[0], res->size);
                } else {
                    cpu_unregister_io_memory(res->io_mem);
                }
            }
        }
    }
}

/*
 * General setup
 */
static int get_vfio_fd(VFIODevice *vdev)
{
    if (vdev->vfiofd_name && strlen(vdev->vfiofd_name) > 0) {
        if (qemu_isdigit(vdev->vfiofd_name[0])) {
            vdev->vfiofd = strtol(vdev->vfiofd_name, NULL, 0);
            return 0;
        } else {
            vdev->vfiofd = monitor_get_fd(cur_mon, vdev->vfiofd_name);
            if (vdev->vfiofd < 0) {
                fprintf(stderr, "%s: (%s) unkown\n", __func__,
                        vdev->vfiofd_name);
                return -1;
            }
            return 0;
        }
    } else {
        char vfio_dir[64], vfio_dev[16];
        DIR *dir;
        struct dirent *de;

        sprintf(vfio_dir, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/vfio/",
                vdev->host.seg, vdev->host.bus,
                vdev->host.dev, vdev->host.func);
        dir = opendir(vfio_dir);
        if (!dir) {
            error_report("vfio: error: Driver not attached\n");
            return -1;
        }

        while ((de = readdir(dir))) {
            if (de->d_name[0] == '.')
                continue;
            if (!strncmp(de->d_name, "vfio", 4))
                break;
        }

        if (!de) {
            error_report("vfio: error: Cannot find vfio* in %s\n", vfio_dir);
            return -1;
        }

        sprintf(vfio_dev, "/dev/%s", de->d_name);
        vdev->vfiofd = open(vfio_dev, O_RDWR);
        if (vdev->vfiofd < 0) {
            error_report("pci-assign: vfio: Failed to open %s: %s\n",
                         vfio_dev, strerror(errno));
            return -1;
        }
        return 0;
    }
}

static int get_uiommu_fd(VFIODevice *vdev)
{
    if (vdev->uiommufd_name && strlen(vdev->uiommufd_name) > 0) {
        if (qemu_isdigit(vdev->uiommufd_name[0])) {
            vdev->uiommufd = strtol(vdev->uiommufd_name, NULL, 0);
            return 0;
        } else {
            vdev->uiommufd = monitor_get_fd(cur_mon, vdev->uiommufd_name);
            if (vdev->uiommufd < 0) {
                fprintf(stderr, "%s: (%s) unkown\n", __func__,
                        vdev->uiommufd_name);
                return -1;
            }
            return 0;
        }
    } else {
        vdev->uiommufd = open("/dev/uiommu", O_RDONLY);
        if (vdev->uiommufd < 0) {
            return -1;
        }
        vdev->uiommufd_name = NULL; /* easier test later */
        return 0;
    }
}

static int vfio_load_rom(VFIODevice *vdev)
{
    uint32_t len, size = PCI_ROM_SLOT;
    char name[32];
    off_t off = 0, voff = vfio_pci_space_to_offset(VFIO_PCI_ROM_RESOURCE);
    ssize_t bytes;
    void *ptr;

    /* If loading ROM from file, pci handles it */
    if (vdev->pdev.romfile || !vdev->pdev.rom_bar)
        return 0;

    if (ioctl(vdev->vfiofd, VFIO_BAR_LEN, &size)) {
        fprintf(stderr, "vfio: VFIO_BAR_LEN failed for OPTION ROM");
        return -1;
    }

    if (!size)
        return 0;

    len = size;
    snprintf(name, sizeof(name), "%s.rom", vdev->pdev.qdev.info->name);
    vdev->pdev.rom_offset = qemu_ram_alloc(&vdev->pdev.qdev, name, size);
    ptr = qemu_get_ram_ptr(vdev->pdev.rom_offset);
    memset(ptr, 0xff, size);

    while (size) {
        bytes = pread(vdev->vfiofd, ptr + off, size, voff + off);
        if (bytes == 0) {
            break; /* expect that we could get back less than the ROM BAR */
        } else if (bytes > 0) {
            off += bytes;
            size -= bytes;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            fprintf(stderr, "vfio: Error reading device ROM: %s\n",
                    strerror(errno));
            qemu_ram_free(vdev->pdev.rom_offset);
            vdev->pdev.rom_offset = 0;
            return -1;
        }
    }

    pci_register_bar(&vdev->pdev, PCI_ROM_SLOT, len, 0, pci_map_option_rom);
    return 0;
}

static int vfio_initfn(struct PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    char sys[64];
    struct stat st;
    int ret;

    /* Check that the host device exists */
    sprintf(sys, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);
    if (stat(sys, &st) < 0) {
        error_report("vfio: error: no such host device "
                     "%04x:%02x:%02x.%01x", vdev->host.seg, vdev->host.bus,
                     vdev->host.dev, vdev->host.func);
        return -1;
    }

    if (get_uiommu_fd(vdev))
        return -1;

    if (get_vfio_fd(vdev))
        goto out_close_uiommu;

    if (ioctl(vdev->vfiofd, VFIO_DOMAIN_SET, &vdev->uiommufd))
        goto out_close_vfiofd;

    /* Get a copy of config space */
    ret = pread(vdev->vfiofd, vdev->pdev.config,
                pci_config_size(&vdev->pdev), VFIO_PCI_CONFIG_OFF);
    if (ret < pci_config_size(&vdev->pdev)) {
        fprintf(stderr, "vfio: Failed to read device config space\n");
        goto out_unset_domain;
    }

    /* Clear host resource mapping info.  If we choose not to register a
     * BAR, such as might be the case with the option ROM, we can get
     * confusing, unwritable, residual addresses from the host here. */
    memset(&vdev->pdev.config[PCI_BASE_ADDRESS_0], 0, 24);
    memset(&vdev->pdev.config[PCI_ROM_ADDRESS], 0, 4);

    vfio_load_rom(vdev);

    if (vfio_setup_msi(vdev))
        goto out_unset_domain;

    if (vfio_setup_resources(vdev))
        goto out_disable_msix;

    if (vfio_map_iommu(vdev))
        goto out_unmap_resources;

    if (vfio_enable_intx(vdev))
        goto out_unmap_iommu;

    return 0;

out_unmap_iommu:
    vfio_unmap_iommu(vdev);
out_unmap_resources:
    vfio_unmap_resources(vdev);
out_disable_msix:
    vfio_teardown_msi(vdev);
out_unset_domain:
    ioctl(vdev->vfiofd, VFIO_DOMAIN_UNSET);
out_close_vfiofd:
    close(vdev->vfiofd);
out_close_uiommu:
    if (!vdev->uiommufd_name)
        close(vdev->uiommufd);
    return -1;
}

static int vfio_exitfn(struct PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    vfio_disable_interrupts(vdev);
    vfio_teardown_msi(vdev);
    vfio_unmap_iommu(vdev);
    vfio_unmap_resources(vdev);
    ioctl(vdev->vfiofd, VFIO_DOMAIN_UNSET);
    close(vdev->vfiofd);
    if (!vdev->uiommufd_name)
        close(vdev->uiommufd);
    return 0;
}

static void vfio_reset(DeviceState *dev)
{
    PCIDevice *pdev = DO_UPCAST(PCIDevice, qdev, dev);
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    if (ioctl(vdev->vfiofd, VFIO_RESET_FUNCTION)) {
        fprintf(stderr, "vfio: Error unable to reset physical device "
                "(%04x:%02x:%02x.%x): %s\n", vdev->host.seg, vdev->host.bus,
                vdev->host.dev, vdev->host.func, strerror(errno));
    }
}

static PropertyInfo qdev_prop_hostaddr = {
    .name  = "pci-hostaddr",
    .type  = -1,
    .size  = sizeof(PCIHostDevice),
    .parse = parse_hostaddr,
    .print = print_hostaddr,
};

static PCIDeviceInfo vfio_info = {
    .qdev.name    = "vfio",
    .qdev.desc    = "pass through host pci devices to the guest via vfio",
    .qdev.size    = sizeof(VFIODevice),
    .qdev.reset   = vfio_reset,
    .init         = vfio_initfn,
    .exit         = vfio_exitfn,
    .config_read  = vfio_pci_read_config,
    .config_write = vfio_pci_write_config,
    .qdev.props   = (Property[]) {
        DEFINE_PROP("host", VFIODevice, host,
                    qdev_prop_hostaddr, PCIHostDevice),
        DEFINE_PROP_STRING("vfiofd", VFIODevice, vfiofd_name),
        DEFINE_PROP_STRING("uiommufd", VFIODevice, uiommufd_name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void vfio_register_devices(void)
{
    pci_qdev_register(&vfio_info);
}

device_init(vfio_register_devices)
