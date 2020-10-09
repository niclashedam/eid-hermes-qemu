/*
 * Eid-Hermes eBPF-based PCIe Accelerator
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define HERMES_BAR0_SIZE          (32 * MiB)
#define HERMES_EHVER_OFF     0x00
#define HERMES_EHTS_OFF      0x04
#define HERMES_EHENG_OFF     0x08
#define HERMES_EHPSLOT_OFF   0x09
#define HERMES_EHDSLOT_OFF   0x0A
#define HERMES_EHPSOFF_OFF   0x0C
#define HERMES_EHPSSZE_OFF   0x10
#define HERMES_EHDSOFF_OFF   0x14
#define HERMES_EHDSSZE_OFF   0x18

#define HERMES_EHVER_VAL     1
#define HERMES_EHTS_VAL      1602198883
#define HERMES_EHENG_VAL     1
#define HERMES_EHPSLOT_VAL   16
#define HERMES_EHDSLOT_VAL   32
#define HERMES_EHPSSZE_VAL   (1 * MiB)
#define HERMES_EHDSSZE_VAL   (1 * MiB)
#define HERMES_EHPSOFF_VAL   0
#define HERMES_EHDSOFF_VAL   (HERMES_EHPSSZE_VAL * HERMES_EHPSLOT_VAL)

struct hermes_bar0 {
    uint32_t ehver;
    uint32_t ehts;

    uint8_t eheng;
    uint8_t ehpslot;
    uint8_t ehdslot;
    uint8_t rsv0;

    uint32_t ehdsoff;
    uint32_t ehdssze;
    uint32_t ehpsoff;
    uint32_t ehpssze;

    MemoryRegion mem_reg;
};

typedef struct {
    PCIDevice pdev;
    struct hermes_bar0 *bar0;
} HermesState;

static uint64_t hermes_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    HermesState *hermes = opaque;
    uint32_t *ptr;
    uint32_t val = 0;

    if (addr <= HERMES_EHPSSZE_OFF) {
        ptr = (uint32_t *) &((uint8_t *) hermes->bar0)[addr];
        val = *ptr;
        switch (size) {
        case 1:
            val &= 0xFF;
            break;
        case 2:
            val &= 0xFFFF;
            break;
        }
    }

    return val;
}

/* BAR 0 is read-only */
static void hermes_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
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
    HermesState *hermes = HERMES(obj);

    hermes->bar0 = malloc(sizeof(*hermes->bar0));
    if (hermes->bar0) {
        hermes->bar0->ehver = HERMES_EHVER_VAL;
        hermes->bar0->ehts = HERMES_EHTS_VAL;
        hermes->bar0->eheng = HERMES_EHENG_VAL;
        hermes->bar0->ehpslot = HERMES_EHPSLOT_VAL;
        hermes->bar0->ehdslot = HERMES_EHDSLOT_VAL;

        hermes->bar0->ehdssze = HERMES_EHDSSZE_VAL;
        hermes->bar0->ehpssze = HERMES_EHPSSZE_VAL;
        hermes->bar0->ehdsoff = HERMES_EHDSOFF_VAL;
        hermes->bar0->ehpsoff = HERMES_EHPSOFF_VAL;

    } else {
        fprintf(stderr, "Hermes: Failed to allocate memory for BAR 0\n");
    }
    }
}

static void hermes_instance_finalize(Object *obj)
{
    HermesState *hermes = HERMES(obj);
    if (hermes->bar0) {
        free(hermes->bar0);
    }
}

static void pci_hermes_realize(PCIDevice *pdev, Error **errp)
{
    HermesState *hermes = HERMES(pdev);

    if (hermes->bar0) {
        memory_region_init_io(&hermes->bar0->mem_reg, OBJECT(hermes),
                              &hermes_bar0_ops, hermes, "hermes-bar0",
                              HERMES_BAR0_SIZE);
        pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                         &hermes->bar0->mem_reg);
    }
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
    k->device_id = 0x3000;
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
