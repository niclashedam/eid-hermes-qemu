/*
 * Hermes eBPF-based PCIe Accelerator
 * Copyright (c) 2020 Eidetic Communications Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu-version.h"
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "qapi/error.h"

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define HERMES_BAR0_SIZE          (32 * MiB)

typedef struct HermesState HermesState;

static const struct hermes_bar0 {
    uint32_t ehver;
    char ehbld[48];

    uint8_t eheng;
    uint8_t ehpslot;
    uint8_t ehdslot;
    uint8_t rsv0;

    uint32_t ehpsoff;
    uint32_t ehpssze;
    uint32_t ehdsoff;
    uint32_t ehdssze;
} bar0_init = {
    .ehver =  1,
    .ehbld = QEMU_PKGVERSION,
    .eheng = 1,
    .ehpslot = 16,
    .ehdslot = 16,
    .ehpsoff = 0,
    .ehpssze = 1 * MiB,
    .ehdsoff = 16 * MiB, /* must be >= ehpslot * ehpssze */
    .ehdssze = 1 * MiB,
};

struct HermesState{
    PCIDevice pdev;
    MemoryRegion bar0_mem_reg;
    MemoryRegion bar4_mem_reg;
};

static inline void hermes_bar_warn_invalid(unsigned bar, hwaddr addr)
{
    warn_report("Hermes: Accessed invalid BAR%d register: 0x%lX", bar, addr);
}

static inline void hermes_bar_warn_read_only(unsigned bar, hwaddr addr)
{
    warn_report("Hermes: Tried to write to BAR%d read-only register: 0x%lX",
                bar, addr);
}

static uint64_t hermes_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    uint32_t *ptr;
    uint32_t val = 0;

    if (addr + size <= sizeof(struct hermes_bar0)) {
        ptr = (uint32_t *) &((uint8_t *) &bar0_init)[addr];
        val = *ptr;
        switch (size) {
        case 1:
            val &= 0xFF;
            break;
        case 2:
            val &= 0xFFFF;
            break;
        }
    } else {
        hermes_bar_warn_invalid(0, addr);
    }

    return val;
}

/* BAR 0 is read-only */
static void hermes_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    hermes_bar_warn_read_only(0, addr);
}

static const MemoryRegionOps hermes_bar0_ops = {
    .read = hermes_bar0_read,
    .write = hermes_bar0_write,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void hermes_instance_init(Object *obj)
{
}

static void hermes_instance_finalize(Object *obj)
{
}

static void pci_hermes_realize(PCIDevice *pdev, Error **errp)
{
    HermesState *hermes = HERMES(pdev);

    memory_region_init_io(&hermes->bar0_mem_reg, OBJECT(hermes),
                          &hermes_bar0_ops, hermes, "hermes-bar0",
                          HERMES_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &hermes->bar0_mem_reg);

    memory_region_init_ram(&hermes->bar4_mem_reg, OBJECT(hermes),
                           "hermes-bar4",
                           bar0_init.ehdsoff +
                           bar0_init.ehdssze * bar0_init.ehdslot, &error_fatal);

    pci_register_bar(pdev, 4,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH |
            PCI_BASE_ADDRESS_MEM_TYPE_64, &hermes->bar4_mem_reg);
}

static void pci_hermes_uninit(PCIDevice *pdev)
{
}

static void hermes_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_hermes_realize;
    k->exit = pci_hermes_uninit;
    k->vendor_id = 0x1de5; /* Eideticom */
    k->device_id = 0x3000; /* eBPF-based PCIe Accelerator */
    k->revision = 0x1;
    k->class_id = PCI_CLASS_OTHERS;
}

static void pci_hermes_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo hermes_info = {
        .name          = TYPE_PCI_HERMES_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(HermesState),
        .instance_init = hermes_instance_init,
        .instance_finalize = hermes_instance_finalize,
        .class_init    = hermes_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&hermes_info);
}
type_init(pci_hermes_register_types)
