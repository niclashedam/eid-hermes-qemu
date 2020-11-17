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

#ifndef HERMES_CMD_H
#define HERMES_CMD_H

#include <stdint.h>

struct __attribute__((__packed__)) hermes_cmd_req {
    uint8_t opcode;
    uint8_t rsv0;
    uint16_t cid;
    uint32_t rsv1;
    union {
        struct __attribute__((__packed__)) {
            uint8_t slot_type;
            uint8_t slot_id;
            uint16_t rsv;
            uint64_t addr;
            uint32_t len;
        } xdma;
        uint32_t cmd_specific[6];
    };
};

struct __attribute__((__packed__)) hermes_cmd_res {
    uint16_t cid;
    uint8_t status;
    uint8_t rsv0[5];
    union {
        struct __attribute__((__packed__)) {
            uint32_t bytes;
        } xdma;
        uint32_t cmd_specific[2];
    };
};

struct __attribute__((__packed__)) hermes_cmd_req_res {
    struct hermes_cmd_req req;
    struct hermes_cmd_res res;
};

enum hermes_opcode {
    HERMES_REQ_SLOT = 0x00,
    HERMES_REL_SLOT,
    HERMES_WR = 0x10,
    HERMES_RD,
    HERMES_RUN = 0x80,
};

enum hermes_slot_type {
    HERMES_SLOT_PROG,
    HERMES_SLOT_DATA,
};

enum hermes_status {
    HERMES_STATUS_SUCCESS,
    HERMES_STATUS_NO_SPACE,
    HERMES_STATUS_INV_PROG_SLOT,
    HERMES_STATUS_INV_DATA_SLOT,
    HERMES_STATUS_INV_SLOT_TYPE,
    HERMES_STATUS_INV_ADDR,
    HERMES_STATUS_INV_OPCODE,
    HERMES_STATUS_EBPF_ERROR,

    HERMES_GENERIC_ERROR = 0xFF,
};

#endif
