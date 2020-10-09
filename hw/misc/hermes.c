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
#include "trace.h"

#define TYPE_PCI_HERMES_DEVICE "hermes"
#define HERMES(obj)       OBJECT_CHECK(HermesState, obj, TYPE_PCI_HERMES_DEVICE)

#define HERMES_BAR0_SIZE          (32 * MiB)
#define HERMES_BAR2_SIZE          (64 * KiB)

/*
 * We use the XDMA IP for interrupts. For details, see:
 * https://github.com/aws/aws-fpga/tree/master/sdk/linux_kernel_drivers/xdma
 * https://www.xilinx.com/support/documentation/ip_documentation/xdma/v4_1/pg195-pcie-dma.pdf
 */
#define HERMES_MSIX_VEC_NUM       32

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
};

struct hermes_bar2 {
    struct hermes_bar2_dir_reg h2c;
    struct hermes_bar2_dir_reg c2h;
    struct hermes_bar2_irq_reg irq;
    struct hermes_bar2_cfg_reg cfg;
};

struct HermesState {
    PCIDevice pdev;
    MemoryRegion bar0_mem_reg;
    MemoryRegion bar2_mem_reg;
    MemoryRegion bar4_mem_reg;

    struct hermes_bar2 bar2;
};

static const struct hermes_bar2 bar2_init = {
    .h2c = {
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
    },
    .c2h = {
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
    },
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
            /* do_dma */
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
    HermesState *hermes = opaque;
    uint64_t val = ~0ULL;

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        val = hermes_bar2_engine_read(hermes, &hermes->bar2.h2c, addr);
        break;
    case 0x1:
        val = hermes_bar2_engine_read(hermes, &hermes->bar2.c2h, addr);
        break;
    case 0x2:
        val = hermes_bar2_irq_read(hermes, addr);
        break;
    case 0x3:
        val = hermes_bar2_cfg_read(hermes, addr);
        break;
    case 0x4:
        val = hermes_bar2_sgdma_read(hermes, &hermes->bar2.h2c, addr);
        break;
    case 0x5:
        val = hermes_bar2_sgdma_read(hermes, &hermes->bar2.c2h, addr);
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
    HermesState *hermes = opaque;

    trace_hermes_bar2_write(size, addr, val);

    switch ((addr & 0xFFFF) >> 12) {
    case 0x0:
        val = hermes_bar2_engine_write(hermes, &hermes->bar2.h2c, addr, val);
        break;
    case 0x1:
        val = hermes_bar2_engine_write(hermes, &hermes->bar2.c2h, addr, val);
        break;
    case 0x2:
        val = hermes_bar2_irq_write(hermes, addr, val);
        break;
    case 0x3:
        val = hermes_bar2_cfg_write(addr);
        break;
    case 0x4:
        val = hermes_bar2_sgdma_write(hermes, &hermes->bar2.h2c, addr, val);
        break;
    case 0x5:
        val = hermes_bar2_sgdma_write(hermes, &hermes->bar2.c2h, addr, val);
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

static void hermes_instance_init(Object *obj)
{
    HermesState *hermes = HERMES(obj);
    memcpy(&hermes->bar2, &bar2_init, sizeof(bar2_init));
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
