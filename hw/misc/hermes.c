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
#include "hw/pci/msix.h"
#include "qapi/error.h"
#include "trace.h"
#include <ubpf.h>
#include <elf.h>

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define HERMES_BAR0_SIZE          (32 * MiB)
#define HERMES_BAR2_SIZE          (64 * KiB)

#define H2C_CHANNELS              4
#define C2H_CHANNELS              4

#define UBPF_ENGINES              4

/*
 * We use the XDMA IP for interrupts. For details, see:
 * https://github.com/aws/aws-fpga/tree/master/sdk/linux_kernel_drivers/xdma
 * https://www.xilinx.com/support/documentation/ip_documentation/xdma/v4_1/pg195-pcie-dma.pdf
 */
#define HERMES_MSIX_VEC_NUM       32
#define HERMES_MSIX_TABLE_OFFSET  0x8000
#define HERMES_MSIX_PBA_OFFSET    0x8FE0

/*
 * See Xilinx PG195 for more details on these enums and defines
 *
 * For configurable numbers, we match what is used on AWS F1
 */

#define HERMES_ID_CORE              (0x1FC << 20)
#define HERMES_ID_H2C_CHNL          (0x0   << 16)
#define HERMES_ID_C2H_CHNL          (0x1   << 16)
#define HERMES_ID_IRQ               (0x2   << 16)
#define HERMES_ID_CFG               (0x3   << 16)
#define HERMES_ID_H2CSG             (0x4   << 16)
#define HERMES_ID_C2HSG             (0x5   << 16)
#define HERMES_ID_VER_20164         0x05
#define HERMES_CHNL_ALIGN_ADDR      (1 << 16)
#define HERMES_CHNL_ALIGN_LEN_GRAN  (1 << 8)
#define HERMES_CHNL_ALIGN_ADDR_BITS (1 << 6)

#define W1S(old, new) ((old) | (new))
#define W1C(old, new) ((old) & ~(new))

#define HERMES_CMD_STOP           0x0
#define HERMES_CMD_START          0x1
#define HERMES_CMD_NOT_FINISHED   0x0
#define HERMES_CMD_FINISHED       0x1

#define HERMES_OPCODE_REQUEST_SLOT 0x00
#define HERMES_OPCODE_RELEASE_SLOT 0x01
#define HERMES_OPCODE_EXECUTE_SLOT 0x80

#define HERMES_STATUS_SUCCESS           0x00
#define HERMES_STATUS_OUT_OF_SPACE      0x01
#define HERMES_STATUS_INVALID_PROG_SLOT 0x02
#define HERMES_STATUS_INVALID_DATA_SLOT 0x03
#define HERMES_STATUS_INVALID_ADDR      0x04
#define HERMES_STATUS_EBPF_ERROR        0x05
#define HERMES_STATUS_INVALID_OPCODE    0x06

#define HERMES_BAR0_CMD_REQ    0x1000
#define HERMES_BAR0_CMD_CTRL   0x2000

typedef struct HermesState HermesState;

struct __attribute__((__packed__)) hermes_cmd_req {
    uint8_t opcode;
    uint8_t rsv0;
    uint16_t cid;
    uint32_t rsv1;

    uint8_t prog_slot;
    uint8_t data_slot;
    uint16_t rsv2;
    uint32_t prog_len;

    uint8_t rsv3[16];
};

struct __attribute__((__packed__)) hermes_cmd_res {
    uint16_t cid;
    uint8_t status;
    uint8_t rsv[5];

    uint64_t ebpf_ret;
};

struct __attribute__((__packed__)) hermes_cmd
{
    struct hermes_cmd_req req;
    struct hermes_cmd_res res;
};

struct __attribute__((__packed__)) hermes_cmd_ctrl {
    uint8_t ehcmdexec;
    uint8_t ehcmddone;
    uint8_t rsv[6];
};

static struct hermes_bar0 {
    const uint32_t ehver;
    const char ehbld[48];

    const uint8_t eheng;
    const uint8_t ehpslot;
    const uint8_t ehdslot;
    const uint8_t rsv0;

    const uint32_t ehpsoff;
    const uint32_t ehpssze;
    const uint32_t ehdsoff;
    const uint32_t ehdssze;

    struct hermes_cmd commands[UBPF_ENGINES];
    struct hermes_cmd_ctrl cmdctrl[UBPF_ENGINES];
} bar0_init = {
    .ehver =  1,
    .ehbld = QEMU_PKGVERSION,
    .eheng = UBPF_ENGINES,
    .ehpslot = 16,
    .ehdslot = 16,
    .ehpsoff = 0,
    .ehpssze = 1 * MiB,
    .ehdsoff = 16 * MiB, /* must be >= ehpslot * ehpssze */
    .ehdssze = 1 * MiB,
};

/*
 * BAR2 is used to do DMA using the xdma driver
 * (https://github.com/aws/aws-fpga/tree/master/sdk/linux_kernel_drivers/xdma)
 *
 * The specification of BAR 2 can be found on the following document (Tables
 * 35-126):
 * https://www.xilinx.com/support/documentation/ip_documentation/xdma/v4_1/pg195-pcie-dma.pdf
 * (note that in this document it uses BAR1, but here and on AWS we use BAR2)
 *
 * Note that we currently do not support all registers, only those that were
 * actually used by the XDMA driver.
 */
struct hermes_bar2_engine_reg {
    uint32_t identifier;              /* 0x00 */
    uint32_t control;                 /* 0x04, 0x08 and 0x0C */
    uint32_t status;                  /* 0x40 and 0x44 */
    uint32_t cmp_desc_count;          /* 0x48 */
    uint32_t alignment;               /* 0x4C */
    uint32_t inter_enable_mask;       /* 0x90, 0x94 and 0x98 */
};

struct hermes_bar2_irq_reg {
    uint32_t identifier;              /* 0x00 */
    uint32_t user_inter_enable_mask;  /* 0x04, 0x08 and 0x0C */
    uint32_t chnl_inter_enable_mask;  /* 0x10, 0x14 and 0x18 */
    uint32_t user_inter_request;      /* 0x40 */
    uint32_t chnl_inter_request;      /* 0x44 */
    uint32_t user_inter_pending;      /* 0x48 */
    uint32_t chnl_inter_pending;      /* 0x4C */
    uint32_t user_vct_num[4];         /* 0x80 -- 0x8C */
    uint32_t chnl_vct_num[2];         /* 0xA0 -- 0xA4 */
};

struct hermes_bar2_cfg_reg {
    uint32_t identifier;              /* 0x00 */
};

struct hermes_bar2_sgdma_reg {
    hwaddr desc_addr;                 /* 0x80 - 0x84 */
    uint32_t desc_num_adj;            /* 0x88 */
};

struct hermes_bar2_dir_reg {
    struct hermes_bar2_engine_reg channel;
    struct hermes_bar2_sgdma_reg sgdma;
    void (*perform_dma)(HermesState *hermes, hwaddr src_addr, hwaddr dst_addr,
                        dma_addr_t len);
    int irq_vector;
    void *(*entry)(void*);
    char name[16];
    int ch;
    QemuCond dma_cond;
    QemuMutex dma_mutex;
    QemuThread dma_thread;
};

struct hermes_bar2 {
    struct hermes_bar2_dir_reg h2c[H2C_CHANNELS];
    struct hermes_bar2_dir_reg c2h[C2H_CHANNELS];
    struct hermes_bar2_irq_reg irq;
    struct hermes_bar2_cfg_reg cfg;
};

struct hermes_ubpf_eng {
    struct ubpf_vm *engine;
    QemuCond bpf_cond;
    QemuMutex bpf_mutex;
    QemuThread bpf_thread;

    int no;
    char name[16];
};

struct HermesState {
    PCIDevice pdev;
    MemoryRegion bar0_mem_reg;
    MemoryRegion bar2_mem_reg;
    MemoryRegion bar4_mem_reg;

    struct hermes_bar2 bar2;

    bool stopping;

    struct hermes_ubpf_eng ubpf[UBPF_ENGINES];
};

struct hermes_dma_desc {
    uint32_t ctrl;
    uint32_t len;
    hwaddr src_addr;
    hwaddr dst_addr;
    hwaddr nxt_addr;
};

static inline int addr2ch(hwaddr addr)
{
    return (addr & 0xF00) >> 8;
}

static int hermes_execute_descs(HermesState *hermes,
                                struct hermes_bar2_dir_reg *dir,
                                hwaddr *desc_addr, uint8_t *num_desc)
{
    struct hermes_dma_desc *desc;
    int i;

    trace_hermes_dma_num_adj(*num_desc - 1);
    desc = g_new(struct hermes_dma_desc, *num_desc);
    if (!desc) {
        fprintf(stderr, "[Hermes] Failed to alloc memory for DMA descriptor\n");
        return -1;
    }

    /* Read DMA descriptors */
    pci_dma_read(&hermes->pdev, *desc_addr, desc, *num_desc * sizeof(*desc));

    /* DMA all descriptors in this block */
    for (i = 0; i < *num_desc; i++) {
        trace_hermes_dma_desc(desc[i].ctrl, desc[i].len, desc[i].src_addr,
                              desc[i].dst_addr, desc[i].nxt_addr);
        dir->perform_dma(hermes, desc[i].src_addr, desc[i].dst_addr,
                         desc[i].len);
    }

    *desc_addr = desc[*num_desc - 1].nxt_addr;
    *num_desc = 1 + ((desc[*num_desc - 1].ctrl >> 8) & 0x3F);

    g_free(desc);

    return i;
}

static void do_dma(HermesState *hermes, struct hermes_bar2_dir_reg *dir)
{
    struct hermes_bar2 *bar2 = &hermes->bar2;
    struct hermes_bar2_irq_reg *irq = &bar2->irq;
    hwaddr desc_addr;
    uint8_t num_desc;
    int ret;

    /* Set engine as busy */
    atomic_or(&dir->channel.status, 0x1);

    /* Reset number of completed descriptors */
    dir->channel.cmp_desc_count = 0;

    /*
     * There is always at least one descriptor, plus the adjacent ones (which
     * could be 0). Only bits 5:0 of the register are defined
     */
    num_desc = 1 + (dir->sgdma.desc_num_adj & 0x3F);
    desc_addr = dir->sgdma.desc_addr;
    while (desc_addr) {
        ret = hermes_execute_descs(hermes, dir, &desc_addr, &num_desc);
        if (ret < 0) {
            break;
        }

        /* Update number of completed descriptors */
        dir->channel.cmp_desc_count += ret;
    }

    /* Set engine as not busy */
    atomic_and(&dir->channel.status, ~1);

    if (irq->chnl_inter_enable_mask & (dir->irq_vector + 1)) {
        /* Set interrupt source */
        irq->chnl_inter_request =  irq->chnl_inter_enable_mask &
                                   (dir->irq_vector + 1);

        /*
         * Send interrupt. Since we currently have only one channel for H2C and
         * one for C2H, we have that IRQ 0 is H2C and IRQ 1 is C2H
         */
        trace_hermes_msix_notify(dir->irq_vector);
        msix_notify(PCI_DEVICE(hermes), dir->irq_vector);
    }
}

static void hermes_h2c_dma(HermesState *hermes, hwaddr src_addr,
                           hwaddr dst_addr, dma_addr_t len)
{
    void *bar4_base = memory_region_get_ram_ptr(&hermes->bar4_mem_reg);
    trace_hermes_dma("H2C", src_addr, dst_addr, len);
    pci_dma_read(&hermes->pdev, src_addr, bar4_base + dst_addr, len);
}

static void hermes_c2h_dma(HermesState *hermes, hwaddr src_addr,
                           hwaddr dst_addr, dma_addr_t len)
{
    void *bar4_base = memory_region_get_ram_ptr(&hermes->bar4_mem_reg);
    trace_hermes_dma("C2H", src_addr, dst_addr, len);
    pci_dma_write(&hermes->pdev, dst_addr, bar4_base + src_addr, len);
}

static void hermes_dma_thread(HermesState *hermes,
                              struct hermes_bar2_dir_reg *dir)
{
    qemu_mutex_lock(&dir->dma_mutex);
    while (1) {
        qemu_cond_wait(&dir->dma_cond, &dir->dma_mutex);
        if (hermes->stopping) {
            break;
        }
        do_dma(hermes, dir);
    }
    qemu_mutex_unlock(&dir->dma_mutex);
}

static void *hermes_h2c_dma_thread(void *opaque)
{
    struct hermes_bar2_dir_reg *dir = opaque;
    struct hermes_bar2 *bar2 = container_of(dir,
                               struct hermes_bar2, h2c[dir->ch]);
    HermesState *hermes = container_of(bar2, HermesState, bar2);

    hermes_dma_thread(hermes, dir);
    return NULL;
}

static void *hermes_c2h_dma_thread(void *opaque)
{
    struct hermes_bar2_dir_reg *dir = opaque;
    struct hermes_bar2 *bar2 = container_of(dir,
                               struct hermes_bar2, c2h[dir->ch]);
    HermesState *hermes = container_of(bar2, HermesState, bar2);

    hermes_dma_thread(hermes, dir);
    return NULL;
}

static const struct hermes_bar2_dir_reg h2c_init = {
        .channel = {
            .identifier = HERMES_ID_CORE | HERMES_ID_H2C_CHNL | HERMES_ID_VER_20164,
            /*
             * FIXME: We probably want to enable control bits 18:9 (log and stop
             * engine on read/write errors) and maybe 23:19 as well (log and stop
             * on desc error)
             *
             * AWS F1 also enables bits 4:1, so register value is 0x00F83E1E
             *
             * .control = 0x00F83E1E
             */
            .alignment = HERMES_CHNL_ALIGN_ADDR | HERMES_CHNL_ALIGN_LEN_GRAN |
                         HERMES_CHNL_ALIGN_ADDR_BITS,
            /*
             * FIXME: this should match h2c.control
             * .inter_enable_mask = 0x00F83E1E,
             */
        },
        .perform_dma = hermes_h2c_dma,
        .entry = &hermes_h2c_dma_thread,
};

static const struct hermes_bar2_dir_reg c2h_init = {
        .channel = {
            .identifier = HERMES_ID_CORE | HERMES_ID_C2H_CHNL | HERMES_ID_VER_20164,
            /*
             * FIXME: See comment about h2c.control
             *
             * .control = 0x00F83E1E,
             */
            .alignment = HERMES_CHNL_ALIGN_ADDR | HERMES_CHNL_ALIGN_LEN_GRAN |
                         HERMES_CHNL_ALIGN_ADDR_BITS,
            /*
             * FIXME: See comment about h2.inter_enable_mask
             * .inter_enable_mask = 0x00F83E1E,
             */
        },
        .perform_dma = hermes_c2h_dma,
        .entry = &hermes_c2h_dma_thread,
};

static const struct hermes_bar2 bar2_init = {
    .irq = {
        .identifier = HERMES_ID_CORE | HERMES_ID_IRQ | HERMES_ID_VER_20164,
    },
    .cfg = {
        .identifier = HERMES_ID_CORE | HERMES_ID_CFG | HERMES_ID_VER_20164,
    },
};

static inline void hermes_bar_warn_invalid(unsigned bar, hwaddr addr)
{
    warn_report("Hermes: Accessed invalid BAR%d register: 0x%lX", bar, addr);
}

static inline void hermes_bar_warn_invalid_command(int command, int engine)
{
    warn_report("Hermes: Invalid command 0x%X in engine %d", command, engine);
}

static inline void hermes_bar_warn_read_only(unsigned bar, hwaddr addr)
{
    warn_report("Hermes: Tried to write to BAR%d read-only register: 0x%lX",
                bar, addr);
}

static inline void hermes_bar_warn_unimplemented(unsigned bar, hwaddr addr)
{
    warn_report("Hermes: Accessed unimplemented BAR%d register: 0x%lX", bar,
                addr);
}

static inline void mark_exec_finished(HermesState *hermes, int engine)
{
    bar0_init.cmdctrl[engine].ehcmddone = HERMES_CMD_FINISHED;
    bar0_init.cmdctrl[engine].ehcmdexec = HERMES_CMD_STOP;
    trace_hermes_msix_notify(H2C_CHANNELS + C2H_CHANNELS + engine);
    msix_notify(PCI_DEVICE(hermes), H2C_CHANNELS + C2H_CHANNELS + engine);
}

static void hermes_exec(HermesState *hermes, int engine)
{
    struct hermes_cmd *command = &bar0_init.commands[engine];

    void *bar4_base = memory_region_get_ram_ptr(&hermes->bar4_mem_reg);

    char *errmsg;
    int32_t rv;
    uint64_t ret;
    bool elf;

    unsigned char prog_slot = command->req.prog_slot;
    unsigned char data_slot = command->req.data_slot;

    void *program_base = bar4_base + bar0_init.ehpsoff +
                         (prog_slot * bar0_init.ehpssze);
    void *data_base = bar4_base + bar0_init.ehdsoff +
                      (data_slot * bar0_init.ehdssze);

    command->res.cid = command->req.cid;

    if (prog_slot >= bar0_init.ehpslot) {
        command->res.status = HERMES_STATUS_INVALID_PROG_SLOT;
        goto finish_exec;
    }

    if (data_slot >= bar0_init.ehdslot) {
        command->res.status = HERMES_STATUS_INVALID_DATA_SLOT;
        goto finish_exec;
    }

    if (command->req.opcode != HERMES_OPCODE_EXECUTE_SLOT) {
        command->res.status = HERMES_STATUS_INVALID_OPCODE;
        hermes_bar_warn_invalid_command(command->req.opcode, engine);
        goto finish_exec;
    }

    /* If any code is already loaded, unload it */
    ubpf_unload_code(hermes->ubpf[engine].engine);

    /* Check magic number (first 4 bytes), to see if program is in ELF format */
    elf = bar0_init.ehpssze >= SELFMAG
          && !memcmp(program_base, ELFMAG, SELFMAG);
    if (elf) {
        rv = ubpf_load_elf(hermes->ubpf[engine].engine, program_base,
                           command->req.prog_len, &errmsg);
    } else {
        rv = ubpf_load(hermes->ubpf[engine].engine, program_base,
                       command->req.prog_len, &errmsg);
    }

    if (rv < 0) {
        warn_report("%s", errmsg);
        command->res.status = HERMES_STATUS_EBPF_ERROR;
        command->res.ebpf_ret = rv;
        goto finish_exec;
    }

    ret = ubpf_exec(hermes->ubpf[engine].engine, data_base, bar0_init.ehdssze);

    if (ret == UINT64_MAX) {
        command->res.status = HERMES_STATUS_EBPF_ERROR;
    } else {
        command->res.status = HERMES_STATUS_SUCCESS;
    }

    command->res.ebpf_ret = ret;

finish_exec:
    mark_exec_finished(hermes, engine);
    return;
}

static void *hermes_bpf_thread(void *opaque)
{
    struct hermes_ubpf_eng *reg = opaque;
    HermesState *hermes = container_of(reg, HermesState, ubpf[reg->no]);

    qemu_mutex_lock(&reg->bpf_mutex);
    while (1) {
        qemu_cond_wait(&reg->bpf_cond, &reg->bpf_mutex);
        if (hermes->stopping) {
            break;
        }
        hermes_exec(hermes, reg->no);
    }
    qemu_mutex_unlock(&reg->bpf_mutex);

    return NULL;
}

static uint64_t hermes_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    uint32_t *ptr;
    uint32_t val = 0;

    if (addr + size <= 0x48) {
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
    } else if (addr >= HERMES_BAR0_CMD_REQ &&
               addr + size <= HERMES_BAR0_CMD_REQ +
               sizeof(struct hermes_cmd) * UBPF_ENGINES) {
        ptr = (uint32_t *) &((uint8_t *) &bar0_init.commands)
              [addr - HERMES_BAR0_CMD_REQ];
        val = *ptr;
    } else if (addr >= HERMES_BAR0_CMD_CTRL && addr + size
               <= HERMES_BAR0_CMD_CTRL +
               sizeof(struct hermes_cmd_ctrl) * UBPF_ENGINES) {
        ptr = (uint32_t *) &((uint8_t *) &bar0_init.cmdctrl)
              [addr - HERMES_BAR0_CMD_CTRL];
        val = *ptr;
    } else {
        hermes_bar_warn_invalid(0, addr);
    }

    return val;
}

/* BAR 0 is partly read-only */
static void hermes_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    int engine, offset;
    HermesState *hermes = opaque;

    if (addr >= HERMES_BAR0_CMD_REQ && addr < HERMES_BAR0_CMD_CTRL) {
        engine = (addr - HERMES_BAR0_CMD_REQ) / sizeof(struct hermes_cmd);
        offset = (addr - HERMES_BAR0_CMD_REQ) % sizeof(struct hermes_cmd);

        if (engine > UBPF_ENGINES - 1) {
            hermes_bar_warn_invalid(0, addr);
            return;
        }

        memcpy((void *) &bar0_init.commands[engine] + offset, &val, size);
    } else if (addr >= HERMES_BAR0_CMD_CTRL) {
        engine = (addr - HERMES_BAR0_CMD_CTRL) / sizeof(struct hermes_cmd_ctrl);
        offset = (addr - HERMES_BAR0_CMD_CTRL) % sizeof(struct hermes_cmd_ctrl);

        if (engine > UBPF_ENGINES - 1 || offset >= 2) {
            hermes_bar_warn_invalid(0, addr);
            return;
        } else if (offset != 0) {
            hermes_bar_warn_read_only(0, addr);
            return;
        }

        if (val == HERMES_CMD_START) {
            bar0_init.cmdctrl[engine].ehcmddone = HERMES_CMD_NOT_FINISHED;
            qemu_mutex_lock(&hermes->ubpf[engine].bpf_mutex);
            qemu_cond_signal(&hermes->ubpf[engine].bpf_cond);
            qemu_mutex_unlock(&hermes->ubpf[engine].bpf_mutex);
            bar0_init.cmdctrl[engine].ehcmdexec = HERMES_CMD_STOP;
        }
    } else if (addr + size > 0x48) {
        hermes_bar_warn_invalid(0, addr);
    } else {
        hermes_bar_warn_read_only(0, addr);
    }
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

static uint64_t hermes_bar2_engine_read(HermesState *hermes,
                                        struct hermes_bar2_dir_reg *dir,
                                        hwaddr addr)
{
    struct hermes_bar2_engine_reg *reg = &dir->channel;
    hwaddr masked_addr = addr & 0xFF;
    uint64_t val = ~0ULL;

    switch (masked_addr) {
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
    case 0x90:
    case 0x94:
    case 0x98:
        val = reg->inter_enable_mask & 0xFFFFFE;
        break;
    case 0x88:
    case 0x8C:
    case 0xC0:
    case 0xC4:
    case 0xC8:
    case 0xCC:
    case 0xD0:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_engine_write(HermesState *hermes,
                                         struct hermes_bar2_dir_reg *dir,
                                         hwaddr addr, uint32_t val)
{
    struct hermes_bar2_engine_reg *reg = &dir->channel;
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
    case 0x04:
        reg->control = 0x0FFFFE7F & val;
        if (reg->control & 0x1) {
            qemu_mutex_lock(&dir->dma_mutex);
            qemu_cond_signal(&dir->dma_cond);
            qemu_mutex_unlock(&dir->dma_mutex);
        }
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
    case 0x88:
    case 0x8C:
    case 0xC0:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    case 0x00:
    case 0x4c:
    case 0xC8:
    case 0xCC:
    case 0xD0:
        hermes_bar_warn_read_only(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_irq_read(HermesState *hermes, hwaddr addr)
{
    struct hermes_bar2 *bar2 = &hermes->bar2;
    struct hermes_bar2_irq_reg *reg = &bar2->irq;
    hwaddr masked_addr = addr & 0xFF;
    uint64_t val = ~0ULL;

    switch (masked_addr) {
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
    case 0x84:
    case 0x88:
    case 0x8C:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->user_vct_num[(masked_addr - 0x80) / 4] & 0x1F1F1F1F;
        break;
    case 0xA0:
    case 0xA4:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        val = reg->chnl_vct_num[(masked_addr - 0xA0) / 2] & 0x1F1F1F1F;
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_irq_write(HermesState *hermes, hwaddr addr,
                                      uint32_t val)
{
    struct hermes_bar2 *bar2 = &hermes->bar2;
    struct hermes_bar2_irq_reg *reg = &bar2->irq;
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
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
    case 0x84:
    case 0x88:
    case 0x8C:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->user_vct_num[(masked_addr - 0x80) / 4] = val & 0x1F1F1F1F;
        break;
    case 0xA0:
        /* Only bits 28:24, 20:16, 12:8 and 4:0 are defined */
        reg->chnl_vct_num[(masked_addr - 0xA0) / 2] = val & 0x1F1F1F1F;
        break;
    case 0x00:
    case 0x40:
    case 0x44:
    case 0x48:
    case 0x4C:
        hermes_bar_warn_read_only(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_cfg_read(HermesState *hermes, hwaddr addr)
{
    struct hermes_bar2 *bar2 = &hermes->bar2;
    struct hermes_bar2_cfg_reg *reg = &bar2->cfg;
    hwaddr masked_addr = addr & 0xFF;
    uint64_t val = ~0ULL;

    switch (masked_addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x04:
    case 0x08:
    case 0x0C:
    case 0x10:
    case 0x14:
    case 0x18:
    case 0x1C:
    case 0x40:
    case 0x44:
    case 0x60:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_cfg_write(hwaddr addr)
{
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
    case 0x1C:
    case 0x40:
    case 0x44:
    case 0x60:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    case 0x00:
    case 0x04:
    case 0x08:
    case 0x0C:
    case 0x10:
    case 0x14:
    case 0x18:
        hermes_bar_warn_read_only(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return ~0ULL;
}

static uint64_t hermes_bar2_sgdma_read(HermesState *hermes,
                                       struct hermes_bar2_dir_reg *dir,
                                       hwaddr addr)
{
    struct hermes_bar2_sgdma_reg *reg = &dir->sgdma;
    hwaddr masked_addr = addr & 0xFF;
    uint64_t val = ~0ULL;

    switch (masked_addr) {
    case 0x80:
        val = reg->desc_addr & 0xFFFFFFFF;
        break;
    case 0x84:
        val = reg->desc_addr >> 32;
        break;
    case 0x88:
        /* Only bits 5:0 are defined */
        val = reg->desc_num_adj & 0x3F;
        break;
    case 0x00:
    case 0x8C:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_write(HermesState *hermes,
                                        struct hermes_bar2_dir_reg *dir,
                                        hwaddr addr, uint32_t val)
{
    struct hermes_bar2_sgdma_reg *reg = &dir->sgdma;
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
    case 0x80:
        reg->desc_addr |= (val & 0xFFFFFFFF);
        break;
    case 0x84:
        reg->desc_addr |= (((uint64_t) val) << 32);
        break;
    case 0x88:
        /* Only bits 5:0 are defined */
        reg->desc_num_adj = val & 0x3F;
        break;
    case 0x8C:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    case 0x00:
        hermes_bar_warn_read_only(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_common_read(hwaddr addr)
{
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
    case 0x00:
    case 0x10:
    case 0x14:
    case 0x18:
    case 0x20:
    case 0x24:
    case 0x28:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return ~0ULL;
}

static uint64_t hermes_bar2_sgdma_common_write(hwaddr addr)
{
    hwaddr masked_addr = addr & 0xFF;

    switch (masked_addr) {
    case 0x10:
    case 0x14:
    case 0x18:
    case 0x20:
    case 0x24:
    case 0x28:
        hermes_bar_warn_unimplemented(2, addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    return ~0ULL;
}

static uint64_t hermes_bar2_msix_pba_read(hwaddr addr)
{
    hwaddr masked_addr = addr & 0xFFF;

    if (masked_addr <= 0x1FC || masked_addr == 0xFE0) {
        hermes_bar_warn_unimplemented(2, addr);
    } else {
        hermes_bar_warn_invalid(2, addr);
    }

    return ~0ULL;
}

static uint64_t hermes_bar2_msix_pba_write(hwaddr addr)
{
    hwaddr masked_addr = addr & 0xFFF;

    if (masked_addr <= 0x1FC || masked_addr == 0xFE0) {
        hermes_bar_warn_unimplemented(2, addr);
    } else {
        hermes_bar_warn_invalid(2, addr);
    }

    return ~0ULL;
}

static uint64_t hermes_bar2_read(void *opaque, hwaddr addr, unsigned size)
{
    int ch = addr2ch(addr);
    HermesState *hermes = opaque;
    uint64_t val = ~0ULL;

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        if (ch >= H2C_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_engine_read(hermes,
                                          &hermes->bar2.h2c[ch], addr);
        }
        break;
    case 0x1:
        if (ch >= C2H_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_engine_read(hermes,
                                          &hermes->bar2.c2h[ch], addr);
        }
        break;
    case 0x2:
        val = hermes_bar2_irq_read(hermes, addr);
        break;
    case 0x3:
        val = hermes_bar2_cfg_read(hermes, addr);
        break;
    case 0x4:
        if (ch >= H2C_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_sgdma_read(hermes,
                                         &hermes->bar2.h2c[ch], addr);
        }
        break;
    case 0x5:
        if (ch >= C2H_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_sgdma_read(hermes,
                                         &hermes->bar2.c2h[ch], addr);
        }
        break;
    case 0x6:
        val = hermes_bar2_sgdma_common_read(addr);
        break;
    case 0x8:
        val = hermes_bar2_msix_pba_read(addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }

    trace_hermes_bar2_read(size, addr, val);

    return val;
}

static void hermes_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    int ch = addr2ch(addr);
    HermesState *hermes = opaque;

    trace_hermes_bar2_write(size, addr, val);

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        if (ch >= H2C_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_engine_write(hermes,
                                           &hermes->bar2.h2c[ch], addr, val);
        }
        break;
    case 0x1:
        if (ch >= C2H_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_engine_write(hermes,
                                           &hermes->bar2.c2h[ch], addr, val);
        }
        break;
    case 0x2:
        val = hermes_bar2_irq_write(hermes, addr, val);
        break;
    case 0x3:
        val = hermes_bar2_cfg_write(addr);
        break;
    case 0x4:
        if (ch >= H2C_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_sgdma_write(hermes,
                                          &hermes->bar2.h2c[ch], addr, val);
        }
        break;
    case 0x5:
        if (ch >= C2H_CHANNELS) {
            hermes_bar_warn_invalid(2, addr);
        } else {
            val = hermes_bar2_sgdma_write(hermes,
                                          &hermes->bar2.c2h[ch], addr, val);
        }
        break;
    case 0x6:
        val = hermes_bar2_sgdma_common_write(addr);
        break;
    case 0x8:
        val = hermes_bar2_msix_pba_write(addr);
        break;
    default:
        hermes_bar_warn_invalid(2, addr);
        break;
    }
}

static const MemoryRegionOps hermes_bar2_ops = {
    .read = hermes_bar2_read,
    .write = hermes_bar2_write,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void hermes_unuse_msix_vectors(HermesState *hermes, int num_vectors)
{
    int i;
    for (i = 0; i < num_vectors; i++) {
        msix_vector_unuse(PCI_DEVICE(hermes), i);
    }
}

static bool hermes_use_msix_vectors(HermesState *hermes, int num_vectors)
{
    int i, ret;

    for (i = 0; i < num_vectors; i++) {
        ret = msix_vector_use(PCI_DEVICE(hermes), i);
        if (ret < 0) {
            error_report("Failed to use MSI-X vector %d: error %d\n", i, ret);
            hermes_unuse_msix_vectors(hermes, i);
            return false;
        }
    }

    return true;
}

static void hermes_init_msix(HermesState *hermes, Error **errp)
{
    PCIDevice *dev = PCI_DEVICE(hermes);
    Error *err = NULL;

    int ret = msix_init(dev, HERMES_MSIX_VEC_NUM, &hermes->bar2_mem_reg, 2,
                        HERMES_MSIX_TABLE_OFFSET,
                        &hermes->bar2_mem_reg, 2, HERMES_MSIX_PBA_OFFSET,
                        0x0, &error_fatal);
    if (ret < 0) {
        if (ret == -ENOTSUP) {
            warn_report_err(err);
        } else {
            error_propagate(errp, err);
        }
    } else if (!hermes_use_msix_vectors(hermes, HERMES_MSIX_VEC_NUM)) {
        msix_uninit(dev, &hermes->bar2_mem_reg, &hermes->bar2_mem_reg);
    }
}

static void hermes_cleanup_msix(HermesState *hermes)
{
    if (msix_present(PCI_DEVICE(hermes))) {
        hermes_unuse_msix_vectors(hermes, HERMES_MSIX_VEC_NUM);
        msix_uninit(PCI_DEVICE(hermes), &hermes->bar2_mem_reg,
                    &hermes->bar2_mem_reg);
    }
}

static void hermes_instance_init(Object *obj)
{
    int i;
    HermesState *hermes = HERMES(obj);
    memcpy(&hermes->bar2, &bar2_init, sizeof(bar2_init));

    for (i = 0; i < H2C_CHANNELS; i++) {
        memcpy(&hermes->bar2.h2c[i], &h2c_init, sizeof(h2c_init));
        hermes->bar2.h2c[i].irq_vector = i;
        hermes->bar2.h2c[i].ch = i;
        hermes->bar2.h2c[i].channel.identifier |= ((i << 8) & 0xF00);
        sprintf(hermes->bar2.h2c[i].name, "h2c-dma-%u", i);
    }

    for (i = 0; i < C2H_CHANNELS; i++) {
        memcpy(&hermes->bar2.c2h[i], &c2h_init, sizeof(c2h_init));
        hermes->bar2.c2h[i].irq_vector = H2C_CHANNELS + i;
        hermes->bar2.c2h[i].ch = i;
        hermes->bar2.c2h[i].channel.identifier |= ((i << 8) & 0xF00);
        sprintf(hermes->bar2.c2h[i].name, "c2h-dma-%u", i);
    }
}

static void hermes_instance_finalize(Object *obj)
{
}

static void hermes_bar2_init_dir_reg(struct hermes_bar2_dir_reg *dir)
{
    qemu_mutex_init(&dir->dma_mutex);
    qemu_cond_init(&dir->dma_cond);

    qemu_thread_create(&dir->dma_thread, dir->name, dir->entry, dir,
                       QEMU_THREAD_JOINABLE);
}

static void hermes_bar2_destroy_dir_reg(struct hermes_bar2_dir_reg *dir)
{
    qemu_cond_signal(&dir->dma_cond);
    qemu_thread_join(&dir->dma_thread);
    qemu_cond_destroy(&dir->dma_cond);
    qemu_mutex_destroy(&dir->dma_mutex);

}

static void pci_hermes_realize(PCIDevice *pdev, Error **errp)
{
    int i;
    HermesState *hermes = HERMES(pdev);
    Error *err = NULL;

    memory_region_init_io(&hermes->bar0_mem_reg, OBJECT(hermes),
                          &hermes_bar0_ops, hermes, "hermes-bar0",
                          HERMES_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &hermes->bar0_mem_reg);

    memory_region_init_io(&hermes->bar2_mem_reg, OBJECT(hermes),
                          &hermes_bar2_ops, hermes, "hermes-bar2",
                          HERMES_BAR2_SIZE);
    pci_register_bar(pdev, 2,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH |
            PCI_BASE_ADDRESS_MEM_TYPE_64, &hermes->bar2_mem_reg);

    memory_region_init_ram(&hermes->bar4_mem_reg, OBJECT(hermes),
                           "hermes-bar4",
                           bar0_init.ehdsoff +
                           bar0_init.ehdssze * bar0_init.ehdslot, &error_fatal);

    pci_register_bar(pdev, 4,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH |
            PCI_BASE_ADDRESS_MEM_TYPE_64, &hermes->bar4_mem_reg);

    hermes_init_msix(hermes, errp);

    hermes->stopping = false;

    for (i = 0; i < H2C_CHANNELS; i++) {
        hermes_bar2_init_dir_reg(&hermes->bar2.h2c[i]);
    }

    for (i = 0; i < C2H_CHANNELS; i++) {
        hermes_bar2_init_dir_reg(&hermes->bar2.c2h[i]);
    }

    for (i = 0; i < UBPF_ENGINES; i++) {
        hermes->ubpf[i].engine = ubpf_create();
        if (!hermes->ubpf[i].engine) {
            error_setg(&err, "error creating uBPF engine");
            error_propagate(errp, err);
            return;
        }

        hermes->ubpf[i].no = i;

        sprintf(hermes->ubpf[i].name, "ubpf-%u", i);

        qemu_mutex_init(&hermes->ubpf[i].bpf_mutex);
        qemu_cond_init(&hermes->ubpf[i].bpf_cond);

        qemu_thread_create(&hermes->ubpf[i].bpf_thread,
            hermes->ubpf[i].name,
            &hermes_bpf_thread,
            &hermes->ubpf[i],
            QEMU_THREAD_JOINABLE);
    }

    memset(&bar0_init.cmdctrl, 0, UBPF_ENGINES
                                  * sizeof(struct hermes_cmd_ctrl));
    memset(&bar0_init.commands, 0, UBPF_ENGINES
                                  * sizeof(struct hermes_cmd));
}

static void pci_hermes_uninit(PCIDevice *pdev)
{
    int i;
    HermesState *hermes = HERMES(pdev);

    hermes->stopping = true;
    for (i = 0; i < H2C_CHANNELS; i++) {
        hermes_bar2_destroy_dir_reg(&hermes->bar2.h2c[i]);
    }

    for (i = 0; i < C2H_CHANNELS; i++) {
        hermes_bar2_destroy_dir_reg(&hermes->bar2.c2h[i]);
    }

    for (i = 0; i < UBPF_ENGINES; i++) {
        ubpf_destroy(hermes->ubpf[i].engine);

        qemu_cond_signal(&hermes->ubpf[i].bpf_cond);
        qemu_thread_join(&hermes->ubpf[i].bpf_thread);
        qemu_cond_destroy(&hermes->ubpf[i].bpf_cond);
        qemu_mutex_destroy(&hermes->ubpf[i].bpf_mutex);
    }

    hermes_cleanup_msix(hermes);
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
