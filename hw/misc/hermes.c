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
#include "hw/pci/msix.h"
#include "qapi/error.h"
#include "trace.h"

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define HERMES_BAR0_SIZE          (32 * MiB)
#define HERMES_BAR2_SIZE          (64 * KiB)
#define HERMES_BAR4_SIZE          (128 * MiB)

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

#define HERMES_MSIX_VEC_NUM      32
#define HERMES_MSIX_TABLE_OFFSET (0x8000)
#define HERMES_MSIX_PBA_OFFSET   (0x8FE0)

#define W1S(old, new) ((old) | (new))
#define W1C(old, new) ((old) & ~(new))

QEMU_BUILD_BUG_MSG(HERMES_EHDSSZE_VAL * HERMES_EHDSLOT_VAL +
                   HERMES_EHPSSZE_VAL * HERMES_EHPSLOT_VAL > HERMES_BAR4_SIZE,
                   "Hermes: BAR4 is too small, it won't fit all program and data slots");

typedef struct HermesState HermesState;

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

struct hermes_bar2_cfg_reg {
    uint32_t identifier;          /* 0x00 */
    uint32_t busdev;              /* 0x04 */
    uint32_t pcie_mpl;            /* 0x08 */
    uint32_t pcie_mrrs;           /* 0x0C */
    uint32_t sysid;               /* 0x10 */
    uint32_t msi_enable;          /* 0x14 */
    uint32_t pcie_data_w;         /* 0x18 */
    uint32_t pcie_ctrl;           /* 0x1C */
    uint32_t axi_usr_mpl;         /* 0x40 */
    uint32_t axi_usr_mrrs;        /* 0x44 */
    uint32_t write_flush_timeout; /* 0x60 */
};

struct hermes_bar2_sgdma_reg {
    uint32_t identifier;     /* 0x00 */
    uint32_t desc_low_addr;  /* 0x80 */
    uint32_t desc_high_addr; /* 0x84 */
    uint32_t desc_num_adj;   /* 0x88 */
    uint32_t desc_credits;   /* 0x8C */
};

struct hermes_bar2_sgdma_common_reg {
    uint32_t identifier;              /* 0x00 */
    uint32_t desc_ctrl;               /* 0x10, 0x14 and 0x18 */
    uint32_t desc_credit_mode_enable; /* 0x20, 0x24 and 0x28 */
};

struct hermes_bar2_msix_pba_reg {
    uint32_t vec0_addr_low;   /* 0x00 */
    uint32_t vec0_addr_high;  /* 0x04 */
    uint32_t vec0_data;       /* 0x08 */
    uint32_t vec0_ctrl;       /* 0x0C */
    uint32_t vec31_addr_low;  /* 0x1F0 */
    uint32_t vec31_addr_high; /* 0x1F4 */
    uint32_t vec31_data;      /* 0x1F8 */
    uint32_t vec31_ctrl;      /* 0x1FC */
    uint32_t pba;             /* 0xFE0 */
};

struct hermes_bar2 {
    struct hermes_bar2_engine_reg h2c;
    struct hermes_bar2_engine_reg c2h;
    struct hermes_bar2_irq_reg irq;
    struct hermes_bar2_cfg_reg cfg;
    struct hermes_bar2_sgdma_reg h2c_sgdma;
    struct hermes_bar2_sgdma_reg c2h_sgdma;
    struct hermes_bar2_sgdma_common_reg sgdma_common;
    struct hermes_bar2_msix_pba_reg msix_pba;

    MemoryRegion mem_reg;
    HermesState *parent;
};

struct hermes_bar4 {
    MemoryRegion mem_reg;
};

struct hermes_dma_desc {
    uint32_t ctrl;
    uint32_t len;
    uint32_t src_addr_lo;
    uint32_t src_addr_hi;
    uint32_t dst_addr_lo;
    uint32_t dst_addr_hi;
    uint32_t nxt_addr_lo;
    uint32_t nxt_addr_hi;
};

struct HermesState {
    PCIDevice pdev;
    struct hermes_bar0 *bar0;
    struct hermes_bar2 *bar2;
    struct hermes_bar4 *bar4;
};

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

static int __do_dma(struct HermesState *hermes, hwaddr desc_addr,
                       uint8_t num_desc, bool h2c)
{
    struct hermes_dma_desc *desc;
    hwaddr src_addr, dst_addr, nxt_addr;
    uint8_t nxt_adj;
    void *bar4_base = memory_region_get_ram_ptr(&hermes->bar4->mem_reg);

    trace_hermes_dma_num_adj(num_desc - 1);
    desc = malloc(num_desc * sizeof(*desc));
    if (!desc) {
        fprintf(stderr, "[Hermes] Failed to alloc memory for DMA descriptor\n");
        return -1;
    }

    /* Read DMA descriptors */
    pci_dma_read(&hermes->pdev, desc_addr, desc, num_desc * sizeof(*desc));
    for (int i = 0; i < num_desc; i++) {
        trace_hermes_dma_desc(desc[i].ctrl, desc[i].len, desc[i].src_addr_lo,
                              desc[i].src_addr_hi, desc[i].dst_addr_lo,
                              desc[i].dst_addr_hi, desc[i].nxt_addr_lo,
                              desc[i].nxt_addr_hi);
    }

    /* DMA all descriptors in this block */
    for (int i = 0; i < num_desc; i++) {
        src_addr = ((uint64_t) desc[i].src_addr_hi << 32) | desc[i].src_addr_lo;
        dst_addr = ((uint64_t) desc[i].dst_addr_hi << 32) | desc[i].dst_addr_lo;

        if (h2c) {
            trace_hermes_dma("H2C", src_addr, dst_addr);
            pci_dma_read(&hermes->bar2->parent->pdev, src_addr,
                         bar4_base + dst_addr, desc[i].len);
        } else {
            trace_hermes_dma("C2H", src_addr, dst_addr);
            pci_dma_write(&hermes->bar2->parent->pdev, dst_addr,
                          bar4_base + src_addr, desc[i].len);
        }
    }

    nxt_addr = ((uint64_t) desc[num_desc - 1].nxt_addr_hi << 32)
               | desc[num_desc - 1].nxt_addr_lo;
    if (nxt_addr) {
        nxt_adj = (desc[num_desc - 1].ctrl >> 8) & 0x3F;
        num_desc += __do_dma(hermes, nxt_addr, nxt_adj + 1, h2c);
    }

    return num_desc;
}

static void do_dma(struct hermes_bar2 *bar2, bool h2c)
{
    struct hermes_bar2_engine_reg *engine_reg;
    struct hermes_bar2_sgdma_reg *sgdma_reg;
    struct hermes_bar2_irq_reg *irq = &bar2->irq;
    HermesState *hermes = bar2->parent;
    hwaddr desc_addr;
    unsigned irq_vector;
    unsigned num_desc;

    if (h2c) {
        sgdma_reg = &bar2->h2c_sgdma;
        engine_reg = &bar2->h2c;
        irq_vector = 0;
    } else {
        sgdma_reg = &bar2->c2h_sgdma;
        engine_reg = &bar2->c2h;
        irq_vector = 1;
    }

    /* Reset number of completed descriptors */
    engine_reg->cmp_desc_count = 0;

    /* Set engine as busy */
    atomic_or(&engine_reg->status, 0x1);

    /*
     * There is always at least one descriptor, plus the adjacent ones (which
     * could be 0). Only bits 5:0 of the register are defined
     */
    num_desc = 1 + (sgdma_reg->desc_num_adj & 0x3F);
    desc_addr = ((uint64_t) sgdma_reg->desc_high_addr) << 32 |
                sgdma_reg->desc_low_addr;
    num_desc = __do_dma(hermes, desc_addr, num_desc, h2c);

    /* Set number of completed descriptors */
    engine_reg->cmp_desc_count = num_desc;

    /* Set engine as not busy */
    atomic_and(&engine_reg->status, ~1);

    if (irq->chnl_inter_enable_mask & (irq_vector + 1)) {
        /* Set interrupt source */
        irq->chnl_inter_request =  irq->chnl_inter_enable_mask &
                                   (irq_vector + 1);

        /*
         * Send interrupt. Since we currently have only one channel for H2C and
         * one for C2H, we have that IRQ 0 is H2C and IRQ 1 is C2H
         */
        trace_hermes_msix_notify(irq_vector);
        msix_notify(PCI_DEVICE(hermes), irq_vector);
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
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
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
        if (reg->control & 0x1) {
            do_dma(bar2, h2c);
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
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
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
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
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
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_cfg_read(struct hermes_bar2 *bar2, hwaddr addr)
{
    struct hermes_bar2_cfg_reg *reg = &bar2->cfg;
    uint64_t val = ~0ULL;

    switch (addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x04:
        /* Only bits 15:0 are defined */
        val = reg->busdev & 0xFFFF;
        break;
    case 0x08:
        /* Only bits 2:0 are defined */
        val = reg->pcie_mpl & 0x7;
        break;
    case 0x0C:
        /* Only bits 2:0 are defined */
        val = reg->pcie_mrrs & 0x7;
        break;
    case 0x10:
        /* Only bits 15:0 are defined */
        val = reg->sysid & 0xFFFF;
        break;
    case 0x14:
        /* Only bits 2:0 are defined */
        val = reg->msi_enable & 0x7;
        break;
    case 0x18:
        /* Only bits 2:0 are defined */
        val = reg->pcie_data_w & 0x7;
        break;
    case 0x1C:
        /* Only bit 0 is defined */
        val = reg->pcie_ctrl & 0x1;
        break;
    case 0x40:
        /* Only bits 6:4 and 2:0 are defined */
        val = reg->axi_usr_mpl & 0x77;
        break;
    case 0x44:
        /* Only bits 6:4 and 2:0 are defined */
        val = reg->axi_usr_mrrs & 0x77;
        break;
    case 0x60:
        /* Only bits 4:0 are defined */
        val = reg->write_flush_timeout & 0x1F;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_cfg_write(struct hermes_bar2 *bar2, hwaddr addr,
                                      uint32_t val)
{
    struct hermes_bar2_cfg_reg *reg = &bar2->cfg;
    switch (addr) {
    case 0x1C:
        /* Only bit 0 is writable */
        reg->pcie_ctrl = val & 0x1;
        break;
    case 0x40:
        /* Only bits 2:0 are writable */
        reg->axi_usr_mpl = (reg->axi_usr_mpl & ~0x7) & (val & 0x7);
        break;
    case 0x44:
        /* Only bits 2:0 are writable */
        reg->axi_usr_mrrs = (reg->axi_usr_mrrs & ~0x7) & (val & 0x7);
        break;
    case 0x60:
        /* Only bits 4:0 are writable */
        reg->write_flush_timeout = val & 0x1F;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_read(struct hermes_bar2 *bar2, hwaddr addr,
                                       bool h2c)
{
    struct hermes_bar2_sgdma_reg *reg;
    uint64_t val = ~0ULL;

    if (h2c) {
        reg = &bar2->h2c_sgdma;
    } else {
        reg = &bar2->c2h_sgdma;
    }

    switch (addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x80:
        val = reg->desc_low_addr;
        break;
    case 0x84:
        val = reg->desc_high_addr;
        break;
    case 0x88:
        /* Only bits 5:0 are defined */
        val = reg->desc_num_adj & 0x3F;
        break;
    case 0x8C:
        /* Only bits 9:0 are defined */
        val = reg->desc_credits & 0x3FF;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_write(struct hermes_bar2 *bar2, hwaddr addr,
                                        uint32_t val, bool h2c)
{
    struct hermes_bar2_sgdma_reg *reg;

    if (h2c) {
        reg = &bar2->h2c_sgdma;
    } else {
        reg = &bar2->c2h_sgdma;
    }
    switch (addr) {
    case 0x80:
        reg->desc_low_addr = val;
        break;
    case 0x84:
        reg->desc_high_addr = val;
        break;
    case 0x88:
        /* Only bits 5:0 are defined */
        reg->desc_num_adj = val & 0x3F;
        break;
    case 0x8C:
        /* Only bits 9:0 are defined */
        reg->desc_credits = val & 0x3FF;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_common_read(struct hermes_bar2 *bar2,
                                              hwaddr addr)
{
    struct hermes_bar2_sgdma_common_reg *reg = &bar2->sgdma_common;
    uint64_t val = ~0ULL;

    switch (addr) {
    case 0x00:
        val = reg->identifier;
        break;
    case 0x10:
    case 0x14:
    case 0x18:
        /* Only bits 19:16 and 3:0 are defined */
        val = reg->desc_ctrl & 0xF000F;
        break;
    case 0x20:
    case 0x24:
    case 0x28:
        /* Only bits 19:16 and 3:0 are defined */
        val = reg->desc_credit_mode_enable & 0xF000F;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_sgdma_common_write(struct hermes_bar2 *bar2,
                                               hwaddr addr, uint32_t val)
{
    struct hermes_bar2_sgdma_common_reg *reg = &bar2->sgdma_common;

    switch (addr) {
    case 0x10:
        /* Only bits 19:16 and 3:0 are defined */
        reg->desc_ctrl = val & 0xF000F;
        break;
    case 0x14:
        /* W1S. Only bits 19:16 and 3:0 are defined */
        reg->desc_ctrl = W1S(reg->desc_ctrl, val & 0xF000F);
        break;
    case 0x18:
        /* W1C. Only bits 19:16 and 3:0 are defined */
        reg->desc_ctrl = W1C(reg->desc_ctrl, val & 0xF000F);
        break;
    case 0x20:
        /* Only bits 19:16 and 3:0 are defined */
        reg->desc_credit_mode_enable = val & 0xF000F;
        break;
    case 0x24:
        /* W1S. Only bits 19:16 and 3:0 are defined */
        reg->desc_credit_mode_enable = W1S(reg->desc_credit_mode_enable,
                                           val & 0xF000F);
        break;
    case 0x28:
        /* W1C. Only bits 19:16 and 3:0 are defined */
        reg->desc_credit_mode_enable = W1C(reg->desc_credit_mode_enable,
                                           val & 0xF000F);
        break;
    default:
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
                addr, val);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_msix_pba_read(struct hermes_bar2 *bar2, hwaddr addr)
{
    struct hermes_bar2_msix_pba_reg *reg = &bar2->msix_pba;
    uint64_t val = ~0ULL;

    switch (addr) {
    case 0x00:
        val = reg->vec0_addr_low;
        break;
    case 0x04:
        val = reg->vec0_addr_high;
        break;
    case 0x08:
        val = reg->vec0_data;
        break;
    case 0x0C:
        val = reg->vec0_ctrl;
        break;
    case 0x1F0:
        val = reg->vec31_addr_low;
        break;
    case 0x1F4:
        val = reg->vec31_addr_high;
        break;
    case 0x1F8:
        val = reg->vec31_data;
        break;
    case 0x1FC:
        val = reg->vec31_ctrl;
        break;
    case 0xFE0:
        val = reg->pba;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    return val;
}

static uint64_t hermes_bar2_msix_pba_write(struct hermes_bar2 *bar2,
                                           hwaddr addr, uint32_t val)
{
    struct hermes_bar2_msix_pba_reg *reg = &bar2->msix_pba;
    switch (addr) {
    case 0x00:
        reg->vec0_addr_low = val;
        break;
    case 0x04:
        reg->vec0_addr_high = val;
        break;
    case 0x08:
        reg->vec0_data = val;
        break;
    case 0x0C:
        reg->vec0_ctrl = val;
        break;
    case 0x1F0:
        reg->vec31_addr_low = val;
        break;
    case 0x1F4:
        reg->vec31_addr_high = val;
        break;
    case 0x1F8:
        reg->vec31_data = val;
        break;
    case 0x1FC:
        reg->vec31_ctrl = val;
        break;
    case 0xFE0:
        reg->pba = val;
        break;
    default:
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = %0xlx\n",
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
    case 0x3:
        val = hermes_bar2_cfg_read(hermes->bar2, addr & 0xFF);
        break;
    case 0x4:
        val = hermes_bar2_sgdma_read(hermes->bar2, addr & 0xFF, true);
        break;
    case 0x5:
        val = hermes_bar2_sgdma_read(hermes->bar2, addr & 0xFF, false);
        break;
    case 0x6:
        val = hermes_bar2_sgdma_common_read(hermes->bar2, addr & 0xFF);
        break;
    case 0x8:
        val = hermes_bar2_msix_pba_read(hermes->bar2, addr & 0xFFF);
        break;
    default:
        fprintf(stderr, "Hermes: Invalid read. Addr = 0x%lx\n", addr);
        break;
    }

    trace_hermes_bar2_read(size, addr, val);

    return val;
}

static void hermes_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    HermesState *hermes = opaque;

    trace_hermes_bar2_write(size, addr, val);

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
    case 0x3:
        val = hermes_bar2_cfg_write(hermes->bar2, addr & 0xFF, val);
        break;
    case 0x4:
        val = hermes_bar2_sgdma_write(hermes->bar2, addr & 0xFF, val, true);
        break;
    case 0x5:
        val = hermes_bar2_sgdma_write(hermes->bar2, addr & 0xFF, val, false);
        break;
    case 0x6:
        val = hermes_bar2_sgdma_common_write(hermes->bar2, addr & 0xFF, val);
        break;
    case 0x8:
        val = hermes_bar2_msix_pba_write(hermes->bar2, addr & 0xFFF, val);
        break;
    default:
        fprintf(stderr, "Hermes: Invalid write. Addr = 0x%lx Value = 0x%lx\n",
                addr, val);
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

static void bar2_init(HermesState *hermes)
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

    hermes->bar2->cfg.identifier = (0x1FC << 20) | (0x3 << 16) | (0x5);
    hermes->bar2->cfg.busdev = 0;
    hermes->bar2->cfg.pcie_mpl = 1; /* mpl = 256 bytes */
    hermes->bar2->cfg.pcie_mrrs = 2; /* mrrs = 512 bytes */
    hermes->bar2->cfg.sysid = 0x1234;
    hermes->bar2->cfg.msi_enable = 2; /* MSI disabled, MSI-X enabled */
    hermes->bar2->cfg.pcie_data_w = 3; /* 512 bits */
    hermes->bar2->cfg.pcie_ctrl = 1;
    hermes->bar2->cfg.axi_usr_mpl = (0x5 << 4) | (0x5);
    hermes->bar2->cfg.axi_usr_mrrs = (0x5 << 4) | (0x5);

    hermes->bar2->h2c_sgdma.identifier = (0x1FC << 20) | (0x4 << 16) | (0x5);
    hermes->bar2->c2h_sgdma.identifier = (0x1FC << 20) | (0x5 << 16) | (0x5);
    hermes->bar2->sgdma_common.identifier = (0x1FC << 20) | (0x6 << 16) | (0x5);
    hermes->bar2->msix_pba.vec0_ctrl = 0xFFFFFFFF;
    hermes->bar2->msix_pba.vec31_ctrl = 0xFFFFFFFF;

    hermes->bar2->parent = hermes;
}

static void hermes_unuse_msix_vectors(HermesState *hermes, int num_vectors)
{
    int i;
    for (i = 0; i < num_vectors; i++) {
        msix_vector_unuse(PCI_DEVICE(hermes), i);
    }
}

static bool hermes_use_msix_vectors(HermesState *hermes, int num_vectors)
{
    int i;
    for (i = 0; i < num_vectors; i++) {
        int res = msix_vector_use(PCI_DEVICE(hermes), i);
        if (res < 0) {
            trace_hermes_msix_use_vector_fail(i, res);
            hermes_unuse_msix_vectors(hermes, i);
            return false;
        }
    }
    return true;
}

static void hermes_init_msix(HermesState *hermes)
{
    PCIDevice *dev = PCI_DEVICE(hermes);
    int res = msix_init(dev, HERMES_MSIX_VEC_NUM, &hermes->bar2->mem_reg, 2,
                        HERMES_MSIX_TABLE_OFFSET,
                        &hermes->bar2->mem_reg, 2, HERMES_MSIX_PBA_OFFSET,
                        0x0, &error_fatal);
    if (res < 0) {
        trace_hermes_msix_init_fail(res);
    } else {
        if (!hermes_use_msix_vectors(hermes, HERMES_MSIX_VEC_NUM)) {
            msix_uninit(dev, &hermes->bar2->mem_reg, &hermes->bar2->mem_reg);
        }
    }
}

static void hermes_cleanup_msix(HermesState *hermes)
{
    if (msix_present(PCI_DEVICE(hermes))) {
        hermes_unuse_msix_vectors(hermes, HERMES_MSIX_VEC_NUM);
        msix_uninit(PCI_DEVICE(hermes), &hermes->bar2->mem_reg,
                    &hermes->bar2->mem_reg);
    }
}

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

    hermes->bar2 = malloc(sizeof(*hermes->bar2));
    if (hermes->bar2) {
        bar2_init(hermes);
    } else {
        fprintf(stderr, "Hermes: Failed to allocate memory for BAR 2\n");
    }

    hermes->bar4 = malloc(sizeof(*hermes->bar4));
    if (!hermes->bar4) {
        fprintf(stderr, "Hermes: Failed to allocate memory for BAR 4\n");
    }
}

static void hermes_instance_finalize(Object *obj)
{
    HermesState *hermes = HERMES(obj);
    if (hermes->bar0) {
        free(hermes->bar0);
    }
    if (hermes->bar2) {
        free(hermes->bar0);
    }
    if (hermes->bar4) {
        free(hermes->bar4);
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

    if (hermes->bar2) {
        memory_region_init_io(&hermes->bar2->mem_reg, OBJECT(hermes),
                              &hermes_bar2_ops, hermes, "hermes-bar2",
                              HERMES_BAR2_SIZE);
        pci_register_bar(pdev, 2,
                PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH,
                &hermes->bar2->mem_reg);

        hermes_init_msix(hermes);
    }

    if (hermes->bar4) {
        memory_region_init_ram(&hermes->bar4->mem_reg, OBJECT(hermes),
                               "hermes-bar4", HERMES_BAR4_SIZE, &error_fatal);
        pci_register_bar(pdev, 4,
                PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH,
                &hermes->bar4->mem_reg);
    }
}

static void pci_hermes_uninit(PCIDevice *pdev)
{
    HermesState *hermes = HERMES(pdev);

    hermes_cleanup_msix(hermes);
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
