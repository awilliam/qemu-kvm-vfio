#ifndef __VFIO_H__
#define __VFIO_H__

#include "qemu-common.h"
#include "qemu-queue.h"
#include "pci.h"
#include "ioapic.h"

typedef struct PCIHostDevice {
    uint16_t seg;
    uint8_t bus;
    uint8_t dev:5;
    uint8_t func:3;
} PCIHostDevice;

typedef struct PCIResource {
    bool valid;
    bool mem;
    bool msix;
    bool slow;
    uint8_t bar;
    uint64_t size;
    ram_addr_t memory_index[2];  /* cpu_register_physical_memory() index */
    void *r_virtbase[2];         /* mmapped address */
    int io_mem;                  /* cpu_register_io_memory index */
    pcibus_t e_phys;             /* emulated base address */
    pcibus_t e_size;             /* emulated size of region in bytes */
    uint32_t msix_offset;
    int vfiofd;                  /* see vfio_resource_read/write */
} PCIResource;

typedef struct INTx {
    bool pending;
    uint8_t pin;
    int irq;
    EventNotifier interrupt;
    Notifier eoi;
    Notifier update_irq;
} INTx;

struct VFIODevice;

typedef struct MSIVector {
    EventNotifier interrupt;
    struct VFIODevice *vdev;
    int vector;
} MSIVector;

enum {
    INT_NONE = 0,
    INT_INTx = 1,
    INT_MSI  = 2,
    INT_MSIX = 3,
};

typedef struct VFIODevice {
    PCIDevice pdev;
    PCIHostDevice host;
    PCIResource resources[PCI_NUM_REGIONS - 1]; /* No ROM */
    INTx intx;
    MSIVector *msi_vectors;
    int nr_vectors;
    int interrupt;
    int vfiofd;
    int uiommufd;
    char *vfiofd_name;
    char *uiommufd_name;
} VFIODevice;

#endif /* __VFIO_H__ */
