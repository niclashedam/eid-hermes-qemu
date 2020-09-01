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
#include "qemu/error-report.h"
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
#define HERMES_BAR2_SIZE          (64 * KiB)
#define HERMES_BAR4_SIZE          (16 * MiB)
#define HERMES_RAM_SIZE           HERMES_BAR4_SIZE
#define HERMES_MMIO_SIZE          (1 * MiB)
#define HERMES_RAM_OFFSET         (0x0)
#define HERMES_MMIO_OFFSET        (0 * MiB)

#define HERMES_EHVER     0x00
#define HERMES_EHTS      0x04
#define HERMES_EHENG     0x08
#define HERMES_EHPSLOT   0x09
#define HERMES_EHDSLOT   0x0A
#define HERMES_EHDSOFF   0x0C
#define HERMES_EHDSSZE   0x10
#define HERMES_EHPSOFF   0x14
#define HERMES_EHPSSZE   0x18

#define W1S(old, new) ((old) | (new))
#define W1C(old, new) ((old) & ~(new))

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

struct hermes_bar2_engine_reg {
    uint32_t identifier;         /* 0x00 */
    uint32_t control;            /* 0x04, 0x08 and 0x0C */
    uint32_t status;             /* 0x40 and 0x44 */
    uint32_t cmp_desc_count;     /* 0x48 */
    uint32_t alignment;          /* 0x4C */
    uint32_t wb_addr_low;        /* 0x88 */
    uint32_t wb_addr_high;       /* 0x8C */
    uint32_t inter_enable_mask;  /* 0x90, 0x94 and 0x98 */
    uint32_t pmc;                /* 0xC0 */
    uint32_t pcc0;               /* 0xC4 */
    uint32_t pcc1;               /* 0xC4 */
    uint32_t pdc0;               /* 0xCC */
    uint32_t pdc1;               /* 0xD0 */
};

struct hermes_bar2_irq_reg {
    uint32_t identifier;              /* 0x00 */
    uint32_t user_inter_enable_mask;  /* 0x04, 0x08 and 0x0C */
    uint32_t chnl_inter_enable_mask;  /* 0x10, 0x14 and 0x18 */
    uint32_t user_inter_request;      /* 0x40 */
    uint32_t chnl_inter_request;      /* 0x44 */
    uint32_t user_inter_pending;      /* 0x48 */
    uint32_t chnl_inter_pending;      /* 0x4C */
    uint32_t user_vct_num0;           /* 0x80 */
    uint32_t user_vct_num1;           /* 0x84 */
    uint32_t user_vct_num2;           /* 0x88 */
    uint32_t user_vct_num3;           /* 0x8C */
    uint32_t chnl_vct_num0;           /* 0xA0 */
    uint32_t chnl_vct_num1;           /* 0xA4 */
};

struct hermes_bar2 {
    MemoryRegion mem_reg;
    struct hermes_bar2_engine_reg h2c;
    struct hermes_bar2_engine_reg c2h;
    struct hermes_bar2_irq_reg irq;
    struct hermes_bar2_cfg cfg;
    struct hermes_bar2_sgdma h2c_sgdma;
    struct hermes_bar2_sgdma c2h_sgdma;
    struct hermes_bar2_sgdma_common sgdma_common;
    struct hermes_bar2_msix_pba msix_pba;
};

typedef struct {
    PCIDevice pdev;
    struct hermes_bar0 *bar0;
    struct hermes_bar2 *bar2;
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
    HermesState *hermes = opaque;
    uint64_t val = ~0ULL;

    switch (addr) {
    case HERMES_EHVER:
        val = hermes->bar0->ehver;
        break;
    case HERMES_EHTS:
        val = hermes->bar0->ehts;
        break;
    case HERMES_EHENG:
        val = hermes->bar0->eheng;
        break;
    case HERMES_EHPSLOT:
        val = hermes->bar0->ehpslot;
        break;
    case HERMES_EHDSLOT:
        val = hermes->bar0->ehdslot;
        break;
    case HERMES_EHDSOFF:
        val = hermes->bar0->ehdsoff;
        break;
    case HERMES_EHDSSZE:
        val = hermes->bar0->ehdssze;
        break;
    case HERMES_EHPSOFF:
        val = hermes->bar0->ehpsoff;
        break;
    case HERMES_EHPSSZE:
        val = hermes->bar0->ehpssze;
        break;
    }

    return val;
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

static uint64_t hermes_bar2_engine_read(struct hermes_bar2 *bar2, hwaddr addr,
                                        bool h2c)
{
    uint64_t val = ~0ULL;

    struct hermes_bar2_engine_reg *reg;
    if (h2c) {
        reg = &bar2->h2c;
    } else {
        reg = &bar2->c2h;
    }

    switch (addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x04:
    case 0x08:
    case 0x0C:
        val = reg->control;
        break;
    case 0x40:
        val = reg->status & 0xFFFFFF;
        break;
    case 0x44:
        val = reg->status & 0xFFFFFF;
        /* Clear on Read, except bit 0 */
        reg->status = reg->status & 0x1;
        break;
    case 0x48:
        val = reg->cmp_desc_count;
        break;
    case 0x4C:
        val = reg->alignment & 0xFFFFFF;
        break;
    case 0x88:
        val = reg->wb_addr_low;
        break;
    case 0x8C:
        val = reg->wb_addr_high;
        break;
    case 0x90:
    case 0x94:
    case 0x98:
        val = reg->inter_enable_mask & 0xFFFFFE;
        break;
    case 0xC0:
        /* Bits 0 and 2 are RW, bit 1 is WO */
        val = reg->pmc & 0x5;
        break;
    case 0xC4:
        val = reg->pcc0;
        break;
    case 0xC8:
        val = reg->pcc1 & 0xFFFF;
        break;
    case 0xCC:
        val = reg->pdc0;
        break;
    case 0xD0:
        val = reg->pdc1 & 0xFFFF;
        break;
    default:
        fprintf(stderr, "[Hermes] Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_engine_write(struct hermes_bar2 *bar2, hwaddr addr,
                                         uint32_t val, bool h2c)
{
    struct hermes_bar2_engine_reg *reg;

    if (h2c) {
        reg = &bar2->h2c;
    } else {
        reg = &bar2->c2h;
    }

    switch (addr) {
    case 0x04:
        reg->control = 0x0FFFFE7F & val;
        break;
    case 0x08:
        /* W1S */
        reg->control = W1S(reg->control, val);
        break;
    case 0x0C:
        /* W1C */
        reg->control = W1C(reg->control, val);
        break;
    case 0x40:
        /* Bits 31:24 are not in the spec. Bit 0 is RO, bits 23:1 are RW1C */
        reg->status = W1C(reg->status, val) & 0xFFFFFE;
        break;
    case 0x88:
        reg->wb_addr_low = val;
        break;
    case 0x8C:
        reg->wb_addr_high = val;
        break;
    case 0x90:
        /* Bits 31:24 and 0 are not in the spec */
        reg->inter_enable_mask = reg->inter_enable_mask & 0xFFFFFE;
        break;
    case 0x94:
        /* W1S. Bits 31:24 and 0 are not in the spec */
        reg->inter_enable_mask = W1S(reg->inter_enable_mask, val) & 0xFFFFFE;
        break;
    case 0x98:
        /* W1C. Bits 31:24 and 0 are not in the spec */
        reg->inter_enable_mask = W1C(reg->inter_enable_mask, val) & 0xFFFFFE;
        break;
    case 0xC0:
        /* Only bits 2:0 are in the spec */
        reg->pmc = val & 0x7;
        break;
    default:
        fprintf(stderr, "[Hermes] Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_irq_read(struct hermes_bar2 *bar2, hwaddr addr)
{
    struct hermes_bar2_irq_reg *reg = &bar2->irq;
    uint64_t val = ~0ULL;

    switch (addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x04:
        val = reg->user_inter_enable_mask;
        break;
    case 0x10:
        val = reg->chnl_inter_enable_mask;
        break;
    case 0x40:
        val = reg->user_inter_request;
        break;
    case 0x44:
        val = reg->chnl_inter_request;
        break;
    case 0x48:
        val = reg->user_inter_pending;
        break;
    case 0x4C:
        val = reg->chnl_inter_pending;
        break;
    case 0x80:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->user_vct_num0 & 0x1F1F1F1F;
        break;
    case 0x84:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->user_vct_num1 & 0x1F1F1F1F;
        break;
    case 0x88:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->user_vct_num2 & 0x1F1F1F1F;
        break;
    case 0x8C:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->user_vct_num3 & 0x1F1F1F1F;
        break;
    case 0xA0:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->chnl_vct_num0 & 0x1F1F1F1F;
        break;
    case 0xA4:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->chnl_vct_num1 & 0x1F1F1F1F;
        break;
    default:
        fprintf(stderr, "[Hermes] Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_irq_write(struct hermes_bar2 *bar2, hwaddr addr,
                                      uint32_t val)
{
    struct hermes_bar2_irq_reg *reg = &bar2->irq;
    switch (addr) {
    case 0x04:
        reg->user_inter_enable_mask = val;
        break;
    case 0x08:
        reg->user_inter_enable_mask = W1S(reg->user_inter_enable_mask, val);
        break;
    case 0x0C:
        reg->user_inter_enable_mask = W1C(reg->user_inter_enable_mask, val);
        break;
    case 0x10:
        reg->chnl_inter_enable_mask = val;
        break;
    case 0x14:
        reg->chnl_inter_enable_mask = W1S(reg->chnl_inter_enable_mask, val);
        break;
    case 0x18:
        reg->chnl_inter_enable_mask = W1C(reg->chnl_inter_enable_mask, val);
        break;
    case 0x80:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->user_vct_num0 = val & 0x1F1F1F1F;
        break;
    case 0x84:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->user_vct_num1 = val & 0x1F1F1F1F;
        break;
    case 0x88:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->user_vct_num2 = val & 0x1F1F1F1F;
        break;
    case 0x8C:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->user_vct_num3 = val & 0x1F1F1F1F;
        break;
    case 0xA0:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->chnl_vct_num0 = val & 0x1F1F1F1F;
        break;
    case 0xA4:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->chnl_vct_num1 = val & 0x1F1F1F1F;
        break;
    default:
        fprintf(stderr, "[Hermes] Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_read(void *opaque, hwaddr addr, unsigned size)
{
    HermesState *hermes = opaque;
    uint64_t val = ~0ULL;

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        val = hermes_bar2_engine_read(hermes->bar2, addr & 0xFF, true);
        break;
    case 0x1:
        val = hermes_bar2_engine_read(hermes->bar2, addr & 0xFF, false);
        break;
    case 0x2:
        val = hermes_bar2_irq_read(hermes->bar2, addr & 0xFF);
        break;
    }

    return val;
}

static void hermes_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    HermesState *hermes = opaque;

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        hermes_bar2_engine_write(hermes->bar2, addr & 0xFF, val, true);
        break;
    case 0x1:
        hermes_bar2_engine_write(hermes->bar2, addr & 0xFF, val, false);
        break;
    case 0x2:
        val = hermes_bar2_irq_write(hermes->bar2, addr & 0xFF, val);
        break;
    }
}

static const MemoryRegionOps hermes_bar2_ops = {
    .read = hermes_bar2_read,
    .write = hermes_bar2_write,
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

    memory_region_init_io(&hermes->bar0->mem_reg, OBJECT(hermes),
                          &hermes_bar0_ops, hermes, "hermes-bar0",
                          HERMES_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &hermes->bar0->mem_reg);

    memory_region_init_io(&hermes->bar2->mem_reg, OBJECT(hermes),
                          &hermes_bar2_ops, hermes, "hermes-bar2",
                          HERMES_BAR2_SIZE);
    pci_register_bar(pdev, 2,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH,
            &hermes->bar2->mem_reg);

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

static void init_bar2(HermesState *hermes)
{
    hermes->bar2 = calloc(1, sizeof(*hermes->bar2));
    if (!hermes->bar2) {
        fprintf(stderr, "Failed to allocate memory for BAR 2\n");
        return;
    }

    /* All of these match AWS F1 */
    hermes->bar2->h2c.identifier = (0x1FC << 20) | (0x5);
    /*
     * FIXME: We probably want to enable control bits 18:9 (log and stop engine
     * on read/write errors) and maybe 23:19 as well (log and stop on desc
     * error)
     *
     * AWS F1 also enables bits 4:1, so register value is 0x00F83E1E
     *
     * hermes->bar2->h2c.control = 0x00F83E1E
     */
    hermes->bar2->h2c.alignment = 0x00010140;
    /*
     * FIXME: this should match h2c.control
     * hermes->bar2->h2c.inter_enable_mask = 0x00F83E1E;
     */

    hermes->bar2->c2h.identifier = (0x1FC << 20) | (0x1 << 16) | (0x5);
    /*
     * FIXME: See comment about h2c.control
     *
     * hermes->bar2->c2h.control = 0x00F83E1E;
     */
    hermes->bar2->c2h.alignment = 0x00010140;
    /*
     * FIXME: See comment about h2.inter_enable_mask
     * hermes->bar2->c2h.inter_enable_mask = 0x00F83E1E;
     */

    hermes->bar2->irq.identifier = (0x1FC << 20) | (0x2 << 16) | (0x5);
}

static void hermes_instance_init(Object *obj)
{
    HermesState *hermes = HERMES(obj);

    hermes->dma_mask = ~0ULL; /* 64-bit */
    hermes->bar0 = malloc(sizeof(*hermes->bar0));
    if (hermes->bar0) {
        hermes->bar0->ehver = 1;
        hermes->bar0->ehts = 1602198883;
        hermes->bar0->eheng = 1;
        hermes->bar0->ehpslot = 16;
        hermes->bar0->ehdslot = 128;

        hermes->bar0->ehdsoff = 0;
        hermes->bar0->ehdssze = 16 * MiB;
        hermes->bar0->ehpsoff = hermes->bar0->ehdssze *
                                (1 + hermes->bar0->ehdslot);
        hermes->bar0->ehpssze = 1 * MiB;
    } else {
        fprintf(stderr, "Failed to allocate memory for BAR 0\n");
    }
    init_bar2(hermes);
    object_property_add_uint64_ptr(obj, "dma_mask",
                                   &hermes->dma_mask, OBJ_PROP_FLAG_READWRITE);
}

static void hermes_instance_finalize(Object *obj)
{
    HermesState *hermes = HERMES(obj);
    if (hermes->bar0) {
        free(hermes->bar0);
    }
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
        .instance_finalize = hermes_instance_finalize,
        .class_init    = hermes_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&hermes_info);
}
type_init(pci_hermes_register_types)
