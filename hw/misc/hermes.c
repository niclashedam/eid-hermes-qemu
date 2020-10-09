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

#include "qemu/osdep.h"
#include "hw/pci/pci.h"

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

typedef struct {
    PCIDevice pdev;
} HermesState;

static void hermes_instance_init(Object *obj)
{
}

static void hermes_instance_finalize(Object *obj)
{
}

static void pci_hermes_realize(PCIDevice *pdev, Error **errp)
{
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
