/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BFGPALAYOUT_H
#define BFGPALAYOUT_H

#include <bftypes.h>
#include <bfdebug.h>
#include <bferrorcodes.h>

enum e820_type {
    E820_TYPE_RAM       = 1,
    E820_TYPE_RESERVED  = 2,
    E820_TYPE_ACPI      = 3,
    E820_TYPE_NVS       = 4,
    E820_TYPE_UNUSABLE  = 5,
    E820_TYPE_PMEM      = 7
};

/**
 * Below defines the memory map that is used by the guest, and this memory
 * map will be provided to the VMM, which in turn will be provided to the
 * a Linux guest when it boots.
 *
 *           0x0 +----------------------+ ---
 *               | RAM                  |  | RAM (BIOS RAM)
 *       0xE8000 +----------------------+ ---
 *               | Boot Params          |  | Reserved
 *       0xE9000 +----------------------+  |
 *               | CMD Line             |  |
 *       0xEA000 +----------------------+  |
 *               | Initial GDT          |  |
 *       0xEB000 +----------------------+  |
 *               | Free                 |  |
 *      0x100000 +----------------------+ ---
 *               | Linux                |  | RAM
 *           XXX +----------------------+  |
 *               | Usable RAM           |  |
 *    0xXXXXXXXX +----------------------+ ---
 *               |                      |  |
 *    0xFEC00000 +----------------------+ ---
 *               | Free                 |  | Reserved
 *    0xFFFFFFFF +----------------------+ ---
 *
 * All RAM addresses must have backing memory, and must be mapped as RWE as this
 * is memory that the kernel could attempt to use. Reserved memory can be
 * mapped as both RO and RW and does not need backing (meaning this memory does
 * not have to all be mapped). Unusable memory cannot not be mapped.
 */

int64_t
add_e820_entry(void *ptr, uint64_t saddr, uint64_t eaddr, uint32_t type);

/**
 * Setup E820 Map
 *
 * This function uses the add_e820_entry function to tell the guest what the
 * E820 map is
 *
 * @expects size < 0xFDC00000. Right now we do not support more than 4gb of
 *     RAM, so this is the typical limitation for a < 4GB VM as you must remove
 *     BIOS and hardware addresses spaces from your 4GB limit
 *
 * @param vm a pointer to a VM object that is needed by add_e820_entry
 * @param size the amound of RAM given to the VM. Note that this amount does
 *     not include the RAM in the initial BIOS region that is also given to
 *     the VM.
 * @return SUCCESS on success, FAILURE otherwise
 */
static inline int64_t
setup_bootparams_e820_map(void *vm, uint64_t size)
{
    status_t ret = 0;

    if (size >= 0xFDC00000) {
        BFALERT("setup_e820_map: unsupported amount of RAM\n");
        return FAILURE;
    }

    ret |= add_e820_entry(vm, 0x0000000000000000, 0x00000000000E8000, E820_TYPE_RAM);
    ret |= add_e820_entry(vm, 0x00000000000E8000, 0x0000000000100000, E820_TYPE_RESERVED);
    ret |= add_e820_entry(vm, 0x0000000000100000, 0x000100000 + size, E820_TYPE_RAM);
    ret |= add_e820_entry(vm, 0x00000000FEC00000, 0x00000000FFFFFFFF, E820_TYPE_RESERVED);

    if (ret != SUCCESS) {
        BFALERT("setup_e820_map: add_e820_entry failed to add E820 entries\n");
        return FAILURE;
    }

    return SUCCESS;
}

#define BIOS_RAM_ADDR           0x0
#define BIOS_RAM_SIZE           0xE8000

#define BOOT_PARAMS_PAGE_GPA    0xE8000
#define COMMAND_LINE_PAGE_GPA   0xE9000
#define INITIAL_GDT_GPA         0xEA000

#endif
