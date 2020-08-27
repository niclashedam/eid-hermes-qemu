/*
 * QEMU BPF-capable PCI device
 * Copyright (c) 2019 Martin Ichilevici de Oliveira
 *
 * Inspired by QEMU educational PCI device
 * Copyright (c) 2012-2015 Jiri Slaby
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

/*
 * This sample PCIe device shows how to offload eBPF computation using the uBPF
 * library (https://github.com/iovisor/ubpf).
 * A sample driver can be found at https://github.com/iomartin/pci_ubpf_driver
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qapi/visitor.h"
#include "qapi/error.h"
#include <ubpf.h>
#include <elf.h>

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define DMA_SIZE        4096

#define HERMES_OPCODE_OFFSET      0x00
#define HERMES_CTRL_OFFSET        0x01
#define HERMES_LENGTH_OFFSET      0x04
#define HERMES_OFFSET_OFFSET      0x08
#define HERMES_ADDR_OFFSET_LOW    0x0c
#define HERMES_ADDR_OFFSET_HIGH   0x10

#define HERMES_TEXT_LEN_OFFSET    0x100000
#define HERMES_MEM_LEN_OFFSET     0x100004
#define HERMES_TEXT_OFFSET        0x100100
#define HERMES_RET_OFFSET         0x200000
#define HERMES_READY_OFFSET       0x200004
#define HERMES_REGS_OFFSET        0x200008
#define HERMES_MEM_OFFSET         0x400000
#define HERMES_P2P_OFFSET         0x800000

#define HERMES_OFFLOAD_OPCODE_DMA_TEXT      0x00
#define HERMES_OFFLOAD_OPCODE_MOVE_P2P_TEXT 0x01
#define HERMES_OFFLOAD_OPCODE_DMA_DATA      0x02
#define HERMES_OFFLOAD_OPCODE_MOVE_P2P_DATA 0x03
#define HERMES_OFFLOAD_OPCODE_RUN_PROG      0x04
#define HERMES_OFFLOAD_OPCODE_GET_REGS      0x05
#define HERMES_OFFLOAD_OPCODE_DUMP_MEM      0xff

#define HERMES_NOT_READY          0x0
#define HERMES_READY              0x1
#define DMA_DONE                  0x4

#define HERMES_BAR0_SIZE          (32 * MiB)
#define HERMES_BAR4_SIZE          (16 * MiB)
#define HERMES_RAM_SIZE           HERMES_BAR4_SIZE
#define HERMES_MMIO_SIZE          (1 * MiB)
#define HERMES_RAM_OFFSET         (0x0)
#define HERMES_MMIO_OFFSET        (0 * MiB)

typedef struct {
    PCIDevice pdev;
    MemoryRegion hermes_bar0;
    MemoryRegion hermes_bar4;
    MemoryRegion hermes_ram;
    MemoryRegion hermes_mmio;

    struct ubpf_vm *vm;

    QemuThread thread;
    QemuMutex thr_mutex;
    QemuCond thr_cond;
    bool stopping;

#define HERMES_STATUS_COMPUTING    0x01
    uint32_t status;

    struct command {
        uint8_t opcode;
        uint8_t ctrl;
        uint32_t length;
        uint32_t offset;
        uint64_t addr;
    } cmd;
    char dma_buf[DMA_SIZE];
    uint64_t dma_mask;
} HermesState;

/* Function hexDump was copied from https://stackoverflow.com/a/7776146 */
static void hexDump (const char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    /* Output description if given. */
    if (desc != NULL) {
        printf("%s (%d bytes):\n", desc, len);
    }

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }

    /* Process every byte in the data. */
    for (i = 0; i < len; i++) {
        /* Multiple of 16 means new line (with line offset). */

        if ((i % 16) == 0) {
            /* Just don't print ASCII for the zeroth line. */
            if (i != 0) {
                printf("  %s\n", buff);
            }

            /* Output the offset. */
            printf("  %04x ", i);
        }

        /* Now the hex code for the specific character. */
        printf(" %02x", pc[i]);

        /* And store a printable ASCII character for later. */
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }

    /* Pad out last line if not exactly 16 characters. */
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    /* And print the final ASCII bit. */
    printf("  %s\n", buff);
}

/* Execute the eBPF program */
static int hermes_start_program(HermesState *hermes)
{
    char *hermes_ram_ptr =
        (char *) memory_region_get_ram_ptr(&hermes->hermes_ram);
    uint32_t code_len = *(uint32_t *) (hermes_ram_ptr + HERMES_TEXT_LEN_OFFSET);
    uint32_t mem_len =  *(uint32_t *) (hermes_ram_ptr + HERMES_MEM_LEN_OFFSET);
    void *code = hermes_ram_ptr + HERMES_TEXT_OFFSET;
    void *mem  = hermes_ram_ptr + HERMES_MEM_OFFSET + hermes->cmd.offset;
    bool *ready_addr = (bool *) (hermes_ram_ptr + HERMES_READY_OFFSET);
    uint64_t *ret_addr = (uint64_t *) (hermes_ram_ptr + HERMES_RET_OFFSET);

    char *errmsg;
    int32_t rv;
    uint64_t ret;
    bool elf;

    /* This address is checked by the host to see if execution has finished */
    *ready_addr = HERMES_NOT_READY;

    hermes->vm = ubpf_create();
    if (!hermes->vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    /* Check magic number (first 4 bytes), to see if program is in ELF format */
    elf = code_len >= 4 && !memcmp(code, ELFMAG, 4);
    if (elf) {
        rv = ubpf_load_elf(hermes->vm, code, code_len, &errmsg);
    } else {
        rv = ubpf_load(hermes->vm, code, code_len, &errmsg);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        ubpf_destroy(hermes->vm);
        hermes->vm = NULL;
        free(errmsg);
        return 1;
    }

    if (mem_len > 0) {
        ret = ubpf_exec(hermes->vm, mem, mem_len);
    } else {
        ret = ubpf_exec(hermes->vm, NULL, 0);
    }

    *ret_addr = ret;

    ubpf_destroy(hermes->vm);
    hermes->vm = NULL;
    *ready_addr = HERMES_READY;

    return 0;
}

/*
 * Copy data to the .text segment. If inp2p is true, then we copy from the
 * p2pdma area. Otherwise, use DMA to copy from the host.
 */
static void load_text(HermesState *hermes, bool inp2p)
{
    char *hermes_ram_ptr =
        (char *) memory_region_get_ram_ptr(&hermes->hermes_ram);
    void *code = hermes_ram_ptr + HERMES_TEXT_OFFSET;
    uint32_t *code_len = (uint32_t *) (hermes_ram_ptr + HERMES_TEXT_LEN_OFFSET);

    if (inp2p) {
        memcpy(code, hermes_ram_ptr + HERMES_P2P_OFFSET + hermes->cmd.offset,
                hermes->cmd.length);
    } else {
        pci_dma_read(&hermes->pdev, hermes->cmd.addr, code + hermes->cmd.offset,
                hermes->cmd.length);
    }

    if (hermes->cmd.offset == 0) {
        *code_len = hermes->cmd.length;
    } else {
        *code_len += hermes->cmd.length;
    }

    atomic_or(&hermes->cmd.ctrl, DMA_DONE);
}

/*
 * Copy data to the .data segment. If inp2p is true, then we copy from the
 * p2pdma area. Otherwise, use DMA to copy from the host.
 */
static void load_data(HermesState *hermes, bool inp2p)
{
    char *hermes_ram_ptr =
        (char *) memory_region_get_ram_ptr(&hermes->hermes_ram);
    void *mem = hermes_ram_ptr + HERMES_MEM_OFFSET;
    uint32_t *mem_len =  (uint32_t *) (hermes_ram_ptr + HERMES_MEM_LEN_OFFSET);

    if (inp2p) {
        memcpy(mem, hermes_ram_ptr + HERMES_P2P_OFFSET + hermes->cmd.offset,
                hermes->cmd.length);
    } else {
        pci_dma_read(&hermes->pdev, hermes->cmd.addr, mem + hermes->cmd.offset,
                hermes->cmd.length);
    }

    if (hermes->cmd.offset == 0) {
        *mem_len = hermes->cmd.length;
    } else {
        *mem_len += hermes->cmd.length;
    }

    atomic_or(&hermes->cmd.ctrl, DMA_DONE);
}

static inline void run_program(HermesState *hermes)
{
    hermes_start_program(hermes);
}

/*
 * Useful for debugging. Print both the .text and the .data segments to
 * screen (note it is not transferred to the host).
 */
static void dump_memory(HermesState *hermes)
{
    char *hermes_ram_ptr =
        (char *) memory_region_get_ram_ptr(&hermes->hermes_ram);
    uint32_t code_len = *(uint32_t *) (hermes_ram_ptr + HERMES_TEXT_LEN_OFFSET);
    uint32_t mem_len =  *(uint32_t *) (hermes_ram_ptr + HERMES_MEM_LEN_OFFSET);

    hexDump("prog", hermes_ram_ptr + HERMES_TEXT_OFFSET, code_len);
    hexDump("data", hermes_ram_ptr + HERMES_MEM_OFFSET, mem_len);
}

static void process_command(HermesState *hermes)
{
    fprintf(stderr, "Process Command: Opcode: [0x%02x]\t"
                    "Length: [%u]\tAddr: [0x%08lx]\tOffset: [0x%u]\n",
            hermes->cmd.opcode, hermes->cmd.length, hermes->cmd.addr,
            hermes->cmd.offset);

    switch (hermes->cmd.opcode) {
    case HERMES_OFFLOAD_OPCODE_DMA_TEXT:
    case HERMES_OFFLOAD_OPCODE_MOVE_P2P_TEXT:
        load_text(hermes,
                  hermes->cmd.opcode == HERMES_OFFLOAD_OPCODE_MOVE_P2P_TEXT);
        break;
    case HERMES_OFFLOAD_OPCODE_DMA_DATA:
    case HERMES_OFFLOAD_OPCODE_MOVE_P2P_DATA:
        load_data(hermes,
                  hermes->cmd.opcode == HERMES_OFFLOAD_OPCODE_MOVE_P2P_DATA);
        break;
    case HERMES_OFFLOAD_OPCODE_RUN_PROG:
        run_program(hermes);
        break;
    case HERMES_OFFLOAD_OPCODE_DUMP_MEM:
        dump_memory(hermes);
        break;
    default:
        fprintf(stderr, "Invalid opcode: %u\n", hermes->cmd.opcode & 0xff);
    }
}

static uint64_t hermes_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    HermesState *hermes = opaque;
    uint64_t val = ~0ULL;

    switch (addr) {
    case HERMES_OPCODE_OFFSET:
        val = hermes->cmd.opcode;
        break;
    case HERMES_CTRL_OFFSET:
        val = hermes->cmd.ctrl;
        break;
    case HERMES_LENGTH_OFFSET:
        val = hermes->cmd.length;
        break;
    case HERMES_OFFSET_OFFSET:
        val = hermes->cmd.offset;
        break;
    case HERMES_ADDR_OFFSET_LOW:
    case HERMES_ADDR_OFFSET_HIGH:
        val = hermes->cmd.addr;
        break;
    default:
        break;
    }

    return val;
}

static void hermes_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    HermesState *hermes = opaque;

    switch (addr & 0xff) {
    case HERMES_OPCODE_OFFSET:
        hermes->cmd.opcode = val & 0xff;
        break;
    case HERMES_CTRL_OFFSET:
        hermes->cmd.ctrl = val & 0xff;
        qemu_mutex_lock(&hermes->thr_mutex);
        atomic_or(&hermes->status, HERMES_STATUS_COMPUTING);
        qemu_cond_signal(&hermes->thr_cond);
        qemu_mutex_unlock(&hermes->thr_mutex);
        break;
    case HERMES_LENGTH_OFFSET:
        hermes->cmd.length = val;
        break;
    case HERMES_OFFSET_OFFSET:
        hermes->cmd.offset = val;
        break;
    case HERMES_ADDR_OFFSET_LOW:
        hermes->cmd.addr = val;
        break;
    case HERMES_ADDR_OFFSET_HIGH:
        hermes->cmd.addr = (val << 32) | hermes->cmd.addr;
        break;
    }
}

static const MemoryRegionOps hermes_mmio_ops = {
    .read = hermes_mmio_read,
    .write = hermes_mmio_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static uint64_t hermes_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}

static void hermes_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
}

static const MemoryRegionOps hermes_bar0_ops = {
    .read = hermes_bar0_read,
    .write = hermes_bar0_write,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/*
 * We purposely use a thread, so that users are forced to wait for the status
 * register.
 */
static void *hermes_cmd_thread(void *opaque)
{
    HermesState *hermes = opaque;

    while (1) {

        qemu_mutex_lock(&hermes->thr_mutex);
        while ((atomic_read(&hermes->status) & HERMES_STATUS_COMPUTING) == 0 &&
                        !hermes->stopping) {
            qemu_cond_wait(&hermes->thr_cond, &hermes->thr_mutex);
        }

        if (hermes->stopping) {
            qemu_mutex_unlock(&hermes->thr_mutex);
            break;
        }

        process_command(hermes);
        qemu_mutex_unlock(&hermes->thr_mutex);

        atomic_and(&hermes->status, ~HERMES_STATUS_COMPUTING);
    }

    return NULL;
}

static void pci_hermes_realize(PCIDevice *pdev, Error **errp)
{
    HermesState *hermes = HERMES(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    qemu_mutex_init(&hermes->thr_mutex);
    qemu_cond_init(&hermes->thr_cond);
    qemu_thread_create(&hermes->thread, "hermes", hermes_cmd_thread,
                       hermes, QEMU_THREAD_JOINABLE);

    memory_region_init_io(&hermes->hermes_bar0, OBJECT(hermes),
                          &hermes_bar0_ops, hermes, "hermes-bar0",
                          HERMES_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &hermes->hermes_bar0);

    memory_region_init(&hermes->hermes_bar4, OBJECT(hermes), "hermes-bar4",
                       HERMES_BAR4_SIZE);
    memory_region_init_ram(&hermes->hermes_ram, OBJECT(hermes), "hermes-ram",
                           HERMES_RAM_SIZE, &error_fatal);
    memory_region_init_io(&hermes->hermes_mmio, OBJECT(hermes),
                          &hermes_mmio_ops, hermes, "hermes-mmio",
                          HERMES_MMIO_SIZE);
    memory_region_add_subregion_overlap(&hermes->hermes_bar4, HERMES_RAM_OFFSET,
            &hermes->hermes_ram, 1);
    memory_region_add_subregion_overlap(&hermes->hermes_bar4,
            HERMES_MMIO_OFFSET, &hermes->hermes_mmio, 2);
    pci_register_bar(pdev, 4,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH,
            &hermes->hermes_bar4);
}

static void pci_hermes_uninit(PCIDevice *pdev)
{
    HermesState *hermes = HERMES(pdev);

    qemu_mutex_lock(&hermes->thr_mutex);
    hermes->stopping = true;
    qemu_mutex_unlock(&hermes->thr_mutex);
    qemu_cond_signal(&hermes->thr_cond);
    qemu_thread_join(&hermes->thread);

    qemu_cond_destroy(&hermes->thr_cond);
    qemu_mutex_destroy(&hermes->thr_mutex);
}

static void hermes_instance_init(Object *obj)
{
    HermesState *hermes = HERMES(obj);

    hermes->dma_mask = ~0ULL; /* 64-bit */
    object_property_add_uint64_ptr(obj, "dma_mask",
                                   &hermes->dma_mask, OBJ_PROP_FLAG_READWRITE);
}

static void hermes_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_hermes_realize;
    k->exit = pci_hermes_uninit;
    k->vendor_id = 0x1de5; /* Eideticom */
    k->device_id = 0x3000;
    k->revision = 0x10;
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
        .class_init    = hermes_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&hermes_info);
}
type_init(pci_hermes_register_types)
