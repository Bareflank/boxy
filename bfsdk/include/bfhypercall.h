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

#ifndef BFHYPERCALL_H
#define BFHYPERCALL_H

#include <bftypes.h>
#include <bfmemory.h>
#include <bfconstants.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

void
_mv_cpuid(
    uint32_t *eax,
    uint32_t *ebx,
    uint32_t *ecx,
    uint32_t *edx);

uint64_t
_mv_debug_op_out(
    uint64_t const val1,
    uint64_t const val2);

uint64_t
_mv_debug_op_dump_vms(
    uint64_t const vmid);

uint64_t
_mv_debug_op_dump_vps(
    uint64_t const vpid);

uint64_t
_mv_debug_op_dump_vmexit_log(
    uint64_t const vpid);

uint64_t
_mv_handle_op_open_handle(
    uint32_t const version,
    uint64_t *const handle);

uint64_t
_mv_handle_op_close_handle(
    uint64_t const handle);

uint64_t
_mv_vm_properties_op_uuid(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t *const uuid1,
    uint64_t *const uuid2);

uint64_t
_mv_vm_properties_op_vmid(
    uint64_t const handle,
    uint64_t const uuid1,
    uint64_t const uuid2,
    uint64_t *const vmid);

uint64_t
_mv_vm_properties_op_e820(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const revz,
    uint64_t const e820_map_gpa);

uint64_t
_mv_vm_properties_op_set_e820(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const revz,
    uint64_t const e820_map_gpa);

uint64_t
_mv_vm_properties_op_set_pt_uart(
    uint64_t const handle,
    uint64_t const vmid,
    uint16_t const port);

uint64_t
_mv_vm_state_op_initial_reg_val(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const reg,
    uint64_t *const val);

uint64_t
_mv_vm_state_op_set_initial_reg_val(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const reg,
    uint64_t const val);

uint64_t
_mv_vm_state_op_initial_msr_val(
    uint64_t const handle,
    uint64_t const vmid,
    uint32_t const msr,
    uint64_t *const val);

uint64_t
_mv_vm_state_op_set_initial_msr_val(
    uint64_t const handle,
    uint64_t const vmid,
    uint32_t const msr,
    uint64_t const val);

uint64_t
_mv_vm_state_op_gva_to_gpa(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const ptt_gpa,
    uint64_t const gva,
    uint64_t *const gpa,
    uint64_t *const flags);

uint64_t
_mv_vm_state_op_map_range(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa,
    uint64_t const flags_size);

uint64_t
_mv_vm_state_op_unmap_range(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa,
    uint64_t const flags_size);

uint64_t
_mv_vm_state_op_copy_range(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa,
    uint64_t const size);

uint64_t
_mv_vm_state_op_map_mdl(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa,
    uint64_t const flags);

uint64_t
_mv_vm_state_op_unmap_mdl(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa,
    uint64_t const flags);

uint64_t
_mv_vm_state_op_copy_mdl(
    uint64_t const handle,
    uint64_t const src_vmid,
    uint64_t const src_gpa,
    uint64_t const dst_vmid,
    uint64_t const dst_gpa);

uint64_t
_mv_vm_state_op_gpa_flags(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const gpa,
    uint64_t *const flags);

uint64_t
_mv_vm_state_op_set_gpa_flags(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t const gpa,
    uint64_t const flags);

uint64_t
_mv_vm_management_op_create_vm(
    uint64_t const handle,
    uint64_t *const vmid);

uint64_t
_mv_vm_management_op_destroy_vm(
    uint64_t const handle,
    uint64_t const vmid);

uint64_t
_mv_vm_management_op_pause_vm(
    uint64_t const handle,
    uint64_t const vmid);

uint64_t
_mv_vm_management_op_resume_vm(
    uint64_t const handle,
    uint64_t const vmid);

uint64_t
_mv_vp_op_vpid(
    uint64_t const handle,
    uint64_t *const vpid);

uint64_t
_mv_vp_state_op_reg_val(
    uint64_t const handle,
    uint64_t const vpid,
    uint64_t const reg,
    uint64_t *const val);

uint64_t
_mv_vp_state_op_set_reg_val(
    uint64_t const handle,
    uint64_t const vpid,
    uint64_t const reg,
    uint64_t const val);

uint64_t
_mv_vp_state_op_msr_val(
    uint64_t const handle,
    uint64_t const vpid,
    uint32_t const msr,
    uint64_t *const val);

uint64_t
_mv_vp_state_op_set_msr_val(
    uint64_t const handle,
    uint64_t const vpid,
    uint32_t const msr,
    uint64_t const val);

uint64_t
_mv_vp_management_op_create_vp(
    uint64_t const handle,
    uint64_t const vmid,
    uint64_t *const vpid);

uint64_t
_mv_vp_management_op_destroy_vp(
    uint64_t const handle,
    uint64_t const vpid);

uint64_t
_mv_vp_management_op_run_vp(
    uint64_t const handle,
    uint64_t const vpid,
    uint64_t *const reason,
    uint64_t *const arg);

uint64_t
_mv_vp_management_op_kill_vp(
    uint64_t const handle,
    uint64_t const vpid);

uint64_t
_mv_vp_management_op_pause_vp(
    uint64_t const handle,
    uint64_t const vpid);

uint64_t
_mv_vp_management_op_resume_vp(
    uint64_t const handle,
    uint64_t const vpid);

// -----------------------------------------------------------------------------
// Scalar Types
// -----------------------------------------------------------------------------

#define mv_status_t uint64_t
#define mv_uint8_t uint8_t
#define mv_uint16_t uint16_t
#define mv_uint32_t uint32_t
#define mv_uint64_t uint64_t

// -----------------------------------------------------------------------------
// Null
// -----------------------------------------------------------------------------

#define MV_NULL ((void *)0)

// -----------------------------------------------------------------------------
// Specification IDs
// -----------------------------------------------------------------------------

#define MV_SPEC_ID1_VAL ((mv_uint32_t)0x3123764D)

// -----------------------------------------------------------------------------
// Handle Type
// -----------------------------------------------------------------------------

struct mv_handle_t {
    mv_uint64_t hndl;
};

// -----------------------------------------------------------------------------
// Register Type
// -----------------------------------------------------------------------------

enum mv_reg_t {
    mv_reg_t_rax = 0,
    mv_reg_t_rbx = 1,
    mv_reg_t_rcx = 2,
    mv_reg_t_rdx = 3,
    mv_reg_t_rdi = 4,
    mv_reg_t_rsi = 5,
    mv_reg_t_r8 = 6,
    mv_reg_t_r9 = 7,
    mv_reg_t_r10 = 8,
    mv_reg_t_r11 = 9,
    mv_reg_t_r12 = 10,
    mv_reg_t_r13 = 11,
    mv_reg_t_r14 = 12,
    mv_reg_t_r15 = 13,
    mv_reg_t_rbp = 14,
    mv_reg_t_rsp = 15,
    mv_reg_t_rip = 16,
    mv_reg_t_cr0 = 17,
    mv_reg_t_cr2 = 18,
    mv_reg_t_cr3 = 19,
    mv_reg_t_cr4 = 20,
    mv_reg_t_cr8 = 21,
    mv_reg_t_dr0 = 22,
    mv_reg_t_dr1 = 23,
    mv_reg_t_dr2 = 24,
    mv_reg_t_dr3 = 25,
    mv_reg_t_dr4 = 26,
    mv_reg_t_dr5 = 27,
    mv_reg_t_dr6 = 28,
    mv_reg_t_dr7 = 29,
    mv_reg_t_rflags = 30,
    mv_reg_t_es = 31,
    mv_reg_t_es_base_addr = 32,
    mv_reg_t_es_limit = 33,
    mv_reg_t_es_attributes = 34,
    mv_reg_t_cs = 35,
    mv_reg_t_cs_base_addr = 36,
    mv_reg_t_cs_limit = 37,
    mv_reg_t_cs_attributes = 38,
    mv_reg_t_ss = 39,
    mv_reg_t_ss_base_addr = 40,
    mv_reg_t_ss_limit = 41,
    mv_reg_t_ss_attributes = 42,
    mv_reg_t_ds = 43,
    mv_reg_t_ds_base_addr = 44,
    mv_reg_t_ds_limit = 45,
    mv_reg_t_ds_attributes = 46,
    mv_reg_t_fs = 47,
    mv_reg_t_fs_base_addr = 48,
    mv_reg_t_fs_limit = 49,
    mv_reg_t_fs_attributes = 50,
    mv_reg_t_gs = 51,
    mv_reg_t_gs_base_addr = 52,
    mv_reg_t_gs_limit = 53,
    mv_reg_t_gs_attributes = 54,
    mv_reg_t_ldtr = 55,
    mv_reg_t_ldtr_base_addr = 56,
    mv_reg_t_ldtr_limit = 57,
    mv_reg_t_ldtr_attributes = 58,
    mv_reg_t_tr = 59,
    mv_reg_t_tr_base_addr = 60,
    mv_reg_t_tr_limit = 61,
    mv_reg_t_tr_attributes = 62,
    mv_reg_t_gdtr = 63,
    mv_reg_t_gdtr_base_addr = 64,
    mv_reg_t_gdtr_limit = 65,
    mv_reg_t_gdtr_attributes = 66,
    mv_reg_t_idtr = 67,
    mv_reg_t_idtr_base_addr = 68,
    mv_reg_t_idtr_limit = 69,
    mv_reg_t_idtr_attributes = 70,
    mv_reg_t_max = 71,
};

// -----------------------------------------------------------------------------
// GPA Flags
// -----------------------------------------------------------------------------

#define MV_GPA_FLAG_RESERVED_MEM (((mv_uint64_t)1) << 0)
#define MV_GPA_FLAG_CONVENTIONAL_MEM (((mv_uint64_t)1) << 7)
#define MV_GPA_FLAG_UNUSABLE_MEM (((mv_uint64_t)1) << 8)
#define MV_GPA_FLAG_ACPI_RECLAIM_MEM (((mv_uint64_t)1) << 9)
#define MV_GPA_FLAG_ACPI_NVS_MEM (((mv_uint64_t)1) << 10)
#define MV_GPA_FLAG_READ_ACCESS (((mv_uint64_t)1) << 32)
#define MV_GPA_FLAG_WRITE_ACCESS (((mv_uint64_t)1) << 33)
#define MV_GPA_FLAG_EXECUTE_ACCESS (((mv_uint64_t)1) << 34)
#define MV_GPA_FLAG_UNCACHEABLE (((mv_uint64_t)1) << 35)
#define MV_GPA_FLAG_UNCACHEABLE_MINUS (((mv_uint64_t)1) << 36)
#define MV_GPA_FLAG_WRITE_COMBINING (((mv_uint64_t)1) << 37)
#define MV_GPA_FLAG_WRITE_COMBINING_PLUS (((mv_uint64_t)1) << 38)
#define MV_GPA_FLAG_WRITE_THROUGH (((mv_uint64_t)1) << 39)
#define MV_GPA_FLAG_WRITE_BACK (((mv_uint64_t)1) << 40)
#define MV_GPA_FLAG_WRITE_PROTECTED (((mv_uint64_t)1) << 41)
#define MV_GPA_FLAG_PAGE_SIZE_4k (((mv_uint64_t)1) << 42)
#define MV_GPA_FLAG_PAGE_SIZE_2M (((mv_uint64_t)1) << 43)
#define MV_GPA_FLAG_PAGE_SIZE_1G (((mv_uint64_t)1) << 44)
#define MV_GPA_FLAG_DONATE (((mv_uint64_t)1) << 45)
#define MV_GPA_FLAG_ZOMBIE (((mv_uint64_t)1) << 46)

// -----------------------------------------------------------------------------
// Memory Descriptor Lists
// -----------------------------------------------------------------------------

#define MV_MDL_MAP_MAX_NUM_ENTRIES ((mv_uint64_t)169)

struct mv_mdl_entry_t {
    mv_uint64_t gpa;
    mv_uint64_t size;
    mv_uint64_t flags;
};

struct mv_mdl_t {
    mv_uint64_t num_entries;
    mv_uint64_t next;
    mv_uint64_t revz[3];
    struct mv_mdl_entry_t entries[MV_MDL_MAP_MAX_NUM_ENTRIES];
};

// -----------------------------------------------------------------------------
// Hypervisor Discovery
// -----------------------------------------------------------------------------

#define MV_CPUID_HYPERVISOR_PRESENT (((mv_uint32_t)1) << 31)
#define MV_CPUID_SPEC_ID1 (((mv_uint32_t)1) << 0)

#define MV_CPUID_MIN_LEAF_VAL ((mv_uint32_t)0x40000202)
#define MV_CPUID_MAX_LEAF_VAL ((mv_uint32_t)0x4000FFFF)
#define MV_CPUID_INIT_VAL ((mv_uint32_t)0x40000200)
#define MV_CPUID_INC_VAL ((mv_uint32_t)0x100)
#define MV_CPUID_VENDOR_ID1_VAL ((mv_uint32_t)0x694D6642)
#define MV_CPUID_VENDOR_ID2_VAL ((mv_uint32_t)0x566F7263)

static inline mv_uint32_t
mv_present(mv_uint32_t spec_id)
{
    mv_uint32_t eax;
    mv_uint32_t ebx;
    mv_uint32_t ecx;
    mv_uint32_t edx;
    mv_uint32_t max_leaf;
    mv_uint32_t leaf;

    /**
     * First check to see if software is running on a hypervisor. Although not
     * officially documented by Intel/AMD, bit 31 of the feature identifiers is
     * reserved for hypervisors, and any hypervisor that conforms (at least in
     * part) to the Hypervisor Top Level Functional Specification will set this.
     */

    eax = 0x00000001;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & MV_CPUID_HYPERVISOR_PRESENT) == 0) {
        return 0;
    }

    /**
     * Now that we know that we are running on a hypervisor, the next step is
     * determine how many hypervisor specific CPUID leaves are supported. This
     * is done as follows. Note that the MicroV spec defines the min/max values
     * for the return of this query, which we can also use to determine if this
     * is MicroV.
     */

    eax = 0x40000000;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    max_leaf = eax;
    if (max_leaf < MV_CPUID_MIN_LEAF_VAL || max_leaf > MV_CPUID_MAX_LEAF_VAL) {
        return 0;
    }

    /**
     * Now that we know how many CPUID leaves to parse, we can scan the CPUID
     * leaves for MicroV. Since MicroV also supports the HyperV and Xen
     * interfaces, we start at 0x40000200, and increment by 0x100 until we
     * find MicroV's signature. Normally, the first leaf should be MicroV, but
     * we need to scan just incase future MicroV specs add additional ABIs.
     */

    for (leaf = MV_CPUID_INIT_VAL; leaf < max_leaf; leaf += MV_CPUID_INC_VAL) {
        eax = leaf;
        _mv_cpuid(&eax, &ebx, &ecx, &edx);

        if (ebx == MV_CPUID_VENDOR_ID1_VAL && ecx == MV_CPUID_VENDOR_ID2_VAL) {
            break;
        }
    }

    if (leaf >= max_leaf) {
        return 0;
    }

    /**
     * Finally, we need to verify which version of the spec software speaks and
     * verifying that MicroV also speaks this same spec.
     */

    eax = leaf + 0x00000001U;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    switch (spec_id) {
        case MV_SPEC_ID1_VAL: {
            if ((eax & MV_CPUID_SPEC_ID1) == 0) {
                return 0;
            }

            break;
        }

        default:
            return 0;
    }

    /**
     * If we got this far, it means that software is running on MicroV, and
     * both MicroV and software speak the same specification, which means
     * software may proceed with communicating with MicroV. The next step is
     * to open an handle and use it for additional hypercalls.
     */

    return 1;
}

// -----------------------------------------------------------------------------
// Hypercall Status Codes
// -----------------------------------------------------------------------------

static inline mv_status_t
mv_status_sig(mv_status_t const status)
{
    return (status & 0xFFFF000000000000);
}

static inline mv_status_t
mv_status_flags(mv_status_t const status)
{
    return (status & 0x0000FFFFFFFF0000);
}

static inline mv_status_t
mv_status_value(mv_status_t const status)
{
    return (status & 0x000000000000FFFF);
}

#define MV_STATUS_SUCCESS ((mv_status_t)0x0000000000000000)
#define MV_STATUS_FAILURE_UNKNOWN ((mv_status_t)0xDEAD000000010001)
#define MV_STATUS_FAILURE_UNKNOWN_HYPERCALL ((mv_status_t)0xDEAD000000020001)
#define MV_STATUS_FAILURE_INVALID_HANDLE ((mv_status_t)0xDEAD000000040001)
#define MV_STATUS_FAILURE_UNSUPPORTED_HYPERCALL ((mv_status_t)0xDEAD000000080001)
#define MV_STATUS_FAILURE_UNSUPPORTED_FLAGS ((mv_status_t)0xDEAD000000100001)
#define MV_STATUS_FAILURE_UNSUPPORTED_SPED_ID ((mv_status_t)0xDEAD000000200001)
#define MV_STATUS_INVALID_PERM_VMID ((mv_status_t)0xDEAD000000010002)
#define MV_STATUS_INVALID_PERM_DENIED ((mv_status_t)0xDEAD000000020002)
#define MV_STATUS_INVALID_PARAMS0 ((mv_status_t)0xDEAD000000010003)
#define MV_STATUS_INVALID_PARAMS1 ((mv_status_t)0xDEAD000000020003)
#define MV_STATUS_INVALID_PARAMS2 ((mv_status_t)0xDEAD000000040003)
#define MV_STATUS_INVALID_PARAMS3 ((mv_status_t)0xDEAD000000080003)
#define MV_STATUS_INVALID_PARAMS4 ((mv_status_t)0xDEAD000000100003)
#define MV_STATUS_INVALID_PARAMS5 ((mv_status_t)0xDEAD000000200003)
#define MV_STATUS_INVALID_GPA_NULL ((mv_status_t)0xDEAD000000010004)
#define MV_STATUS_INVALID_GPA_OUT_OF_RANGE ((mv_status_t)0xDEAD000000020004)
#define MV_STATUS_INVALID_GPA_ALIGNMENT ((mv_status_t)0xDEAD000000040004)
#define MV_STATUS_INVALID_SIZE_ZERO ((mv_status_t)0xDEAD000000010005)
#define MV_STATUS_INVALID_SIZE_OUT_OF_RANGE ((mv_status_t)0xDEAD000000020005)
#define MV_STATUS_INVALID_SIZE_ALIGNMENT ((mv_status_t)0xDEAD000000040005)
#define MV_STATUS_RETRY_CONTINUATION ((mv_status_t)0xDEAD000000010006)
#define MV_STATUS_INVALID_VMID_UNKNOWN ((mv_status_t)0xDEAD000000010007)
#define MV_STATUS_INVALID_VMID_UNSUPPORTED_ROOT ((mv_status_t)0xDEAD000000020007)
#define MV_STATUS_INVALID_VMID_UNSUPPORTED_SELF ((mv_status_t)0xDEAD000000040007)
#define MV_STATUS_INVALID_VMID_UNSUPPORTED_GLOBAL_STORE ((mv_status_t)0xDEAD000000080007)
#define MV_STATUS_INVALID_VMID_UNSUPPORTED_ANY ((mv_status_t)0xDEAD000000100007)
#define MV_STATUS_INVALID_UUID_UNKNOWN ((mv_status_t)0xDEAD000000010008)
#define MV_STATUS_INVALID_UUID_UNSUPPORTED_ROOT ((mv_status_t)0xDEAD000000020008)
#define MV_STATUS_INVALID_UUID_UNSUPPORTED_SELF ((mv_status_t)0xDEAD000000040008)
#define MV_STATUS_INVALID_UUID_UNSUPPORTED_GLOBAL_STORE ((mv_status_t)0xDEAD000000080008)
#define MV_STATUS_INVALID_UUID_UNSUPPORTED_ANY ((mv_status_t)0xDEAD000000100008)
#define MV_STATUS_INVALID_VPID_UNKNOWN ((mv_status_t)0xDEAD000000010009)
#define MV_STATUS_INVALID_VPID_UNSUPPORTED_SELF ((mv_status_t)0xDEAD000000020009)
#define MV_STATUS_INVALID_VPID_UNSUPPORTED_PARENT ((mv_status_t)0xDEAD000000040009)
#define MV_STATUS_INVALID_VPID_UNSUPPORTED_ANY ((mv_status_t)0xDEAD000000080009)

// -----------------------------------------------------------------------------
// Hypercall Inputs
// -----------------------------------------------------------------------------

#define MV_HYPERCALL_SIG_VAL ((mv_uint64_t)0x764D000000000000)
#define MV_OP_SHIFT ((mv_uint32_t)16)

#define MV_HYPERCALL_FLAGS_SCC (((mv_uint64_t)1) << 32)

static inline mv_uint64_t
mv_hypercall_sig(mv_uint64_t const rax)
{
    return (rax & 0xFFFF000000000000);
}

static inline mv_uint64_t
mv_hypercall_flags(mv_uint64_t const rax)
{
    return (rax & 0x0000FFFF00000000);
}

static inline mv_uint64_t
mv_hypercall_opcode(mv_uint64_t const rax)
{
    return (rax & 0xFFFF0000FFFF0000);
}

static inline mv_uint64_t
mv_hypercall_index(mv_uint64_t const rax)
{
    return (rax & 0x000000000000FFFF);
}

// -----------------------------------------------------------------------------
// Hypercall Opcodes - Debug Support
// -----------------------------------------------------------------------------

#define MV_DEBUG_OP_VAL ((mv_uint64_t)0x764D000000000000)
#define MV_DEBUG_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000000000)

// -----------------------------------------------------------------------------
// Hypercall Opcodes - Handle Support
// -----------------------------------------------------------------------------

#define MV_HANDLE_OP_VAL ((mv_uint64_t)0x764D000000010000)
#define MV_HANDLE_OP_NOSIG_VAL ((mv_uint64_t)0x000000000010000)

// -----------------------------------------------------------------------------
// Hypercall Opcodes - Virtual Machines
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_VAL ((mv_uint64_t)0x764D000000020000)
#define MV_VM_PROPERTIES_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000020000)

#define MV_VM_STATE_OP_VAL ((mv_uint64_t)0x764D000000030000)
#define MV_VM_STATE_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000030000)

#define MV_VM_MANAGEMENT_OP_VAL ((mv_uint64_t)0x764D000000040000)
#define MV_VM_MANAGEMENT_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000040000)

#define MV_VM_KV_OP_VAL ((mv_uint64_t)0x764D000000050000)
#define MV_VM_KV_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000050000)

// -----------------------------------------------------------------------------
// Hypercall Opcodes - Virtual Processors
// -----------------------------------------------------------------------------

#define MV_VP_PROPERTIES_OP_VAL ((mv_uint64_t)0x764D000000060000)
#define MV_VP_PROPERTIES_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000060000)

#define MV_VP_STATE_OP_VAL ((mv_uint64_t)0x764D000000070000)
#define MV_VP_STATE_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000070000)

#define MV_VP_MANAGEMENT_OP_VAL ((mv_uint64_t)0x764D000000080000)
#define MV_VP_MANAGEMENT_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000080000)

#define MV_VP_EXIT_OP_VAL ((mv_uint64_t)0x764D000000090000)
#define MV_VP_EXIT_OP_NOSIG_VAL ((mv_uint64_t)0x0000000000090000)

// -----------------------------------------------------------------------------
// mv_debug_op_out
// -----------------------------------------------------------------------------

#define MV_DEBUG_OP_OUT_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_debug_op_out(
    mv_uint64_t const val1,    /* IN */
    mv_uint64_t const val2)    /* IN */
{
    return _mv_debug_op_out(val1, val2);
}

// -----------------------------------------------------------------------------
// mv_debug_op_dump_vms
// -----------------------------------------------------------------------------

#define MV_DEBUG_OP_DUMP_VMS_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_debug_op_dump_vms(
    mv_uint64_t const vmid)    /* IN */
{
    return _mv_debug_op_dump_vms(vmid);
}

// -----------------------------------------------------------------------------
// mv_debug_op_dump_vps
// -----------------------------------------------------------------------------

#define MV_DEBUG_OP_DUMP_VPS_IDX_VAL ((mv_uint64_t)0x0000000000000002)

static inline mv_status_t
mv_debug_op_dump_vps(
    mv_uint64_t const vpid)    /* IN */
{
    return _mv_debug_op_dump_vps(vpid);
}

// -----------------------------------------------------------------------------
// mv_debug_op_dump_vmexit_log
// -----------------------------------------------------------------------------

#define MV_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL ((mv_uint64_t)0x0000000000000003)

static inline mv_status_t
mv_debug_op_dump_vmexit_log(
    mv_uint64_t const vpid)    /* IN */
{
    return _mv_debug_op_dump_vmexit_log(vpid);
}

// -----------------------------------------------------------------------------
// mv_handle_op_open_handle
// -----------------------------------------------------------------------------

#define MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_handle_op_open_handle(
    mv_uint32_t const version,           /* IN */
    struct mv_handle_t *const handle)    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_handle_op_open_handle(version, &handle->hndl);
}

// -----------------------------------------------------------------------------
// mv_handle_op_close_handle
// -----------------------------------------------------------------------------

#define MV_HANDLE_OP_CLOSE_HANDLE_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_handle_op_close_handle(
    struct mv_handle_t const *const handle)    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_handle_op_close_handle(handle->hndl);
}

// -----------------------------------------------------------------------------
// VMID
// -----------------------------------------------------------------------------

#define MV_VMID_ROOT ((mv_uint64_t)0x0000000000000000)
#define MV_VMID_SELF ((mv_uint64_t)0xFFFFFFFFFFFFFFF0)
#define MV_VMID_GLOBAL_STORE ((mv_uint64_t)0xFFFFFFFFFFFFFFF1)
#define MV_VMID_ANY ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)

// -----------------------------------------------------------------------------
// UUID
// -----------------------------------------------------------------------------

#define MV_UUID1_ROOT ((mv_uint64_t)0x0000000000000000)
#define MV_UUID2_ROOT ((mv_uint64_t)0x0000000000000000)
#define MV_UUID1_SELF ((mv_uint64_t)0xFFFFFFFFFFFFFFF0)
#define MV_UUID2_SELF ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)
#define MV_UUID1_GLOBAL_STORE ((mv_uint64_t)0xFFFFFFFFFFFFFFF1)
#define MV_UUID2_GLOBAL_STORE ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)
#define MV_UUID1_ANY ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)
#define MV_UUID2_ANY ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)

// -----------------------------------------------------------------------------
// mv_vm_op_uuid
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_UUID_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vm_properties_op_uuid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t *const uuid1,                  /* OUT */
    mv_uint64_t *const uuid2)                  /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == uuid1) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    if (MV_NULL == uuid2) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_properties_op_uuid(handle->hndl, vmid, uuid1, uuid2);
}

// -----------------------------------------------------------------------------
// mv_vm_op_vmid
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_VMID_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_vm_properties_op_vmid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const uuid1,                   /* IN */
    mv_uint64_t const uuid2,                   /* IN */
    mv_uint64_t *const vmid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vmid) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_properties_op_vmid(handle->hndl, uuid1, uuid2, vmid);
}

// -----------------------------------------------------------------------------
// mv_vm_properties_is_root_vm
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_properties_is_guest_vm
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_properties_state
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_properties_op_e820
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_E820_IDX_VAL ((mv_uint64_t)0x0000000000000005)

static inline mv_status_t
mv_vm_properties_op_e820(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint64_t const revz,                     /* IN */
    mv_uint64_t const e820_map_gpa)             /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_e820(handle->hndl, vmid, revz, e820_map_gpa);
}

// -----------------------------------------------------------------------------
// mv_vm_properties_op_set_e820
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_SET_E820_IDX_VAL ((mv_uint64_t)0x0000000000000006)

static inline mv_status_t
mv_vm_properties_op_set_e820(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint64_t const revz,                     /* IN */
    mv_uint64_t const e820_map_gpa)             /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_set_e820(
               handle->hndl, vmid, revz, e820_map_gpa);
}

// -----------------------------------------------------------------------------
// mv_vm_properties_op_set_pt_uart
// -----------------------------------------------------------------------------

#define MV_VM_PROPERTIES_OP_SET_PT_UART_IDX_VAL                                \
    ((mv_uint64_t)0x0000000000000007)

static inline mv_status_t
mv_vm_properties_op_set_pt_uart(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint16_t const port)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_set_pt_uart(handle->hndl, vmid, port);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_initial_reg_val
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_INITIAL_REG_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vm_state_op_initial_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_initial_reg_val(handle->hndl, vmid, reg, val);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_set_initial_reg_val
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_SET_INITIAL_REG_VAL_IDX_VAL                             \
    ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_vm_state_op_set_initial_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_set_initial_reg_val(handle->hndl, vmid, reg, val);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_list_of_initial_reg_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_state_op_set_list_of_initial_reg_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_state_op_initial_msr_val
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_INITIAL_MSR_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000004)

static inline mv_status_t
mv_vm_state_op_initial_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_initial_msr_val(handle->hndl, vmid, msr, val);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_set_initial_msr_val
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_SET_INITIAL_MSR_VAL_IDX_VAL                             \
    ((mv_uint64_t)0x0000000000000005)

static inline mv_status_t
mv_vm_state_op_set_initial_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_set_initial_msr_val(handle->hndl, vmid, msr, val);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_list_of_initial_msr_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_state_op_set_list_of_initial_msr_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_state_op_gva_to_gpa
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_GVA_TO_GPA_IDX_VAL ((mv_uint64_t)0x00000000000000008)

static inline mv_status_t
mv_vm_state_op_gva_to_gpa(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const ptt_gpa,                 /* IN */
    mv_uint64_t const gva,                     /* IN */
    mv_uint64_t *const gpa,                    /* OUT */
    mv_uint64_t *const flags)                  /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == gpa) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    if (MV_NULL == flags) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_gva_to_gpa(
               handle->hndl, vmid, ptt_gpa, gva, gpa, flags);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_map_range
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_MAP_RANGE_IDX_VAL ((mv_uint64_t)0x00000000000000009)

static inline mv_status_t
mv_vm_state_op_map_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags_size)              /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_map_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags_size);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_unmap_range
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_UNMAP_RANGE_IDX_VAL ((mv_uint64_t)0x0000000000000000A)

static inline mv_status_t
mv_vm_state_op_unmap_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags_size)              /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_unmap_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags_size);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_copy_range
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_COPY_RANGE_IDX_VAL ((mv_uint64_t)0x0000000000000000B)

static inline mv_status_t
mv_vm_state_op_copy_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const size)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_copy_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, size);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_map_mdl
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_MAP_MDL_IDX_VAL ((mv_uint64_t)0x0000000000000000C)

static inline mv_status_t
mv_vm_state_op_map_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags)                   /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_map_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_unmap_mdl
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_UNMAP_MDL_IDX_VAL ((mv_uint64_t)0x0000000000000000D)

static inline mv_status_t
mv_vm_state_op_unmap_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags)                   /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_unmap_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_copy_mdl
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_COPY_MDL_IDX_VAL ((mv_uint64_t)0x0000000000000000E)

static inline mv_status_t
mv_vm_state_op_copy_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa)                 /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_copy_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_gpa_flags
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_GPA_FLAGS_IDX_VAL ((mv_uint64_t)0x0000000000000000F)

static inline mv_status_t
mv_vm_state_op_gpa_flags(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const gpa,                     /* IN */
    mv_uint64_t *const flags)                  /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == flags) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_gpa_flags(handle->hndl, vmid, gpa, flags);
}

// -----------------------------------------------------------------------------
// mv_vm_state_op_set_gpa_flags
// -----------------------------------------------------------------------------

#define MV_VM_STATE_OP_SET_GPA_FLAGS_IDX_VAL ((mv_uint64_t)0x00000000000000010)

static inline mv_status_t
mv_vm_state_op_set_gpa_flags(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const gpa,                     /* IN */
    mv_uint64_t const flags)                   /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_set_gpa_flags(handle->hndl, vmid, gpa, flags);
}

// -----------------------------------------------------------------------------
// mv_vm_management_op_create_vm
// -----------------------------------------------------------------------------

#define MV_VM_MANAGEMENT_OP_CREATE_VM_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vm_management_op_create_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t *const vmid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vmid) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_vm_management_op_create_vm(handle->hndl, vmid);
}

// -----------------------------------------------------------------------------
// mv_vm_management_op_destroy_vm
// -----------------------------------------------------------------------------

#define MV_VM_MANAGEMENT_OP_DESTROY_VM_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_vm_management_op_destroy_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_destroy_vm(handle->hndl, vmid);
}

// -----------------------------------------------------------------------------
// mv_vm_management_op_pause_vm
// -----------------------------------------------------------------------------

#define MV_VM_MANAGEMENT_OP_PAUSE_VM_IDX_VAL ((mv_uint64_t)0x00000000000000002)

static inline mv_status_t
mv_vm_management_op_pause_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_pause_vm(handle->hndl, vmid);
}

// -----------------------------------------------------------------------------
// mv_vm_management_op_resume_vm
// -----------------------------------------------------------------------------

#define MV_VM_MANAGEMENT_OP_RESUME_VM_IDX_VAL ((mv_uint64_t)0x00000000000000003)

static inline mv_status_t
mv_vm_management_op_resume_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_resume_vm(handle->hndl, vmid);
}

// -----------------------------------------------------------------------------
// mv_vm_kv_op_open
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_close
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_read_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_write_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_read_range
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_write_range
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_read_mdl
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_write_mdl
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_global_store
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vm_kv_op_set_global_store
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// VMID
// -----------------------------------------------------------------------------

#define MV_VPID_SELF ((mv_uint64_t)0xFFFFFFFFFFFFFFF0)
#define MV_VPID_PARENT ((mv_uint64_t)0xFFFFFFFFFFFFFFF1)
#define MV_VPID_ANY ((mv_uint64_t)0xFFFFFFFFFFFFFFFF)

// -----------------------------------------------------------------------------
// mv_vp_op_vpid
// -----------------------------------------------------------------------------

#define MV_VP_OP_VPID_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vp_op_vpid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t *const vpid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vpid) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_vp_op_vpid(handle->hndl, vpid);
}

// -----------------------------------------------------------------------------
// mv_vp_op_vmid
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_op_uuid
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_op_is_root_vp
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_op_is_guest_vp
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_op_state
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_reg_val
// -----------------------------------------------------------------------------

#define MV_VP_STATE_OP_REG_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vp_state_op_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_state_op_reg_val(handle->hndl, vpid, reg, val);
}

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_reg_val
// -----------------------------------------------------------------------------

#define MV_VP_STATE_OP_SET_REG_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_vp_state_op_set_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_state_op_set_reg_val(handle->hndl, vpid, reg, val);
}

// -----------------------------------------------------------------------------
// mv_vp_state_op_list_of_reg_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_list_of_reg_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_msr_val
// -----------------------------------------------------------------------------

#define MV_VP_STATE_OP_MSR_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000004)

static inline mv_status_t
mv_vp_state_op_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_state_op_msr_val(handle->hndl, vpid, msr, val);
}

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_msr_val
// -----------------------------------------------------------------------------

#define MV_VP_STATE_OP_SET_MSR_VAL_IDX_VAL ((mv_uint64_t)0x0000000000000005)

static inline mv_status_t
mv_vp_state_op_set_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_state_op_set_msr_val(handle->hndl, vpid, msr, val);
}

// -----------------------------------------------------------------------------
// mv_vp_state_op_list_of_msr_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_list_of_msr_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_hve_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_hve_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_list_of_hve_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_list_of_hve_vals
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_xsave_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_state_op_set_xsave_val
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// mv_vp_management_op_create_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_CREATE_VP_IDX_VAL ((mv_uint64_t)0x0000000000000000)

static inline mv_status_t
mv_vp_management_op_create_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t *const vpid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vpid) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    return _mv_vp_management_op_create_vp(handle->hndl, vmid, vpid);
}

// -----------------------------------------------------------------------------
// mv_vp_management_op_destroy_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_DESTROY_VP_IDX_VAL ((mv_uint64_t)0x0000000000000001)

static inline mv_status_t
mv_vp_management_op_destroy_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_destroy_vp(handle->hndl, vpid);
}

// -----------------------------------------------------------------------------
// mv_vp_management_op_run_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_RUN_VP_IDX_VAL ((mv_uint64_t)0x0000000000000002)

enum mv_vp_exit_t {
    mv_vp_exit_t_external_interrupt = 0,
    mv_vp_exit_t_yield = 1,
    mv_vp_exit_t_retry = 2,
    mv_vp_exit_t_hlt = 3,
    mv_vp_exit_t_fault = 4,
    mv_vp_exit_t_sync_tsc = 5,
    mv_vp_exit_t_max = 6
};

static inline mv_status_t
mv_vp_management_op_run_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t *const reason,                 /* OUT */
    mv_uint64_t *const arg)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == reason) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    if (MV_NULL == arg) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_management_op_run_vp(handle->hndl, vpid, reason, arg);
}

// -----------------------------------------------------------------------------
// mv_vp_management_op_kill_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_KILL_VP_IDX_VAL ((mv_uint64_t)0x0000000000000003)

static inline mv_status_t
mv_vp_management_op_kill_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_kill_vp(handle->hndl, vpid);
}

// -----------------------------------------------------------------------------
// mv_vp_management_op_pause_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_PAUSE_VP_IDX_VAL ((mv_uint64_t)0x00000000000000004)

static inline mv_status_t
mv_vp_management_op_pause_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_pause_vp(handle->hndl, vpid);
}

// -----------------------------------------------------------------------------
// mv_vp_management_op_resume_vp
// -----------------------------------------------------------------------------

#define MV_VP_MANAGEMENT_OP_RESUME_VP_IDX_VAL ((mv_uint64_t)0x00000000000000005)

static inline mv_status_t
mv_vp_management_op_resume_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_resume_vp(handle->hndl, vpid);
}

// =============================================================================
// !!! WARNING DEPRECATED !!!
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

    uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4) NOEXCEPT;
    uint64_t _vmcall1(void *r1) NOEXCEPT;
    uint64_t _vmcall2(void *r1, void *r2) NOEXCEPT;
    uint64_t _vmcall3(void *r1, void *r2, void *r3) NOEXCEPT;
    uint64_t _vmcall4(void *r1, void *r2, void *r3, void *r4) NOEXCEPT;

#ifdef __cplusplus
}
#endif

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

#define domainid_t uint64_t
#define vcpuid_t uint64_t

#define INVALID_DOMAINID 0xFFFFFFFFFFFFFFFF
#define INVALID_VCPUID 0xFFFFFFFFFFFFFFFF

#define SELF 0xFFFFFFFFFFFFFFFE

// -----------------------------------------------------------------------------
// Opcodes
// -----------------------------------------------------------------------------

#define hypercall_enum_run_op 0x01
#define hypercall_enum_domain_op 0x02
#define hypercall_enum_vcpu_op 0x03
#define hypercall_enum_uart_op 0x04
#define hypercall_enum_virq_op 0x10
#define hypercall_enum_vclock_op 0x11

#define bfopcode(a) ((a & 0x00FF000000000000) >> 48)

// -----------------------------------------------------------------------------
// Run Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_run_op__hlt 1
#define hypercall_enum_run_op__fault 2
#define hypercall_enum_run_op__continue 3
#define hypercall_enum_run_op__yield 4
#define hypercall_enum_run_op__set_wallclock 5

#define run_op_ret_op(a) ((0x000000000000000FULL & a) >> 0)
#define run_op_ret_arg(a) ((0xFFFFFFFFFFFFFFF0ULL & a) >> 4)

static inline vcpuid_t
hypercall_run_op(vcpuid_t vcpuid, uint64_t arg1, uint64_t arg2)
{
    return _vmcall(
               0xBF01000000000000, vcpuid, arg1, arg2
           );
}

// -----------------------------------------------------------------------------
// Uart Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_uart_op__char 1
#define hypercall_enum_uart_op__nhex 2
#define hypercall_enum_uart_op__ndec 3

static inline vcpuid_t
hypercall_uart_char_op(uint16_t port, uint64_t c)
{
    return _vmcall(
               0xBF04000000000000, hypercall_enum_uart_op__char, port, c
           );
}

static inline vcpuid_t
hypercall_uart_nhex_op(uint16_t port, uint64_t val)
{
    return _vmcall(
               0xBF04000000000000, hypercall_enum_uart_op__nhex, port, val
           );
}

static inline vcpuid_t
hypercall_uart_ndec_op(uint16_t port, uint64_t val)
{
    return _vmcall(
               0xBF04000000000000, hypercall_enum_uart_op__ndec, port, val
           );
}

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_domain_op__create_domain 0xBF02000000000100
#define hypercall_enum_domain_op__destroy_domain 0xBF02000000000101

#define hypercall_enum_domain_op__set_uart 0xBF02000000000200
#define hypercall_enum_domain_op__set_pt_uart 0xBF02000000000201
#define hypercall_enum_domain_op__dump_uart 0xBF02000000000202

#define hypercall_enum_domain_op__share_page_r 0xBF02000000000300
#define hypercall_enum_domain_op__share_page_rw 0xBF02000000000301
#define hypercall_enum_domain_op__share_page_rwe 0xBF02000000000303
#define hypercall_enum_domain_op__donate_page_r 0xBF02000000000310
#define hypercall_enum_domain_op__donate_page_rw 0xBF02000000000311
#define hypercall_enum_domain_op__donate_page_rwe 0xBF02000000000313

#define hypercall_enum_domain_op__rax 0xBF02000000010000
#define hypercall_enum_domain_op__set_rax 0xBF02000000010001
#define hypercall_enum_domain_op__rbx 0xBF02000000010010
#define hypercall_enum_domain_op__set_rbx 0xBF02000000010011
#define hypercall_enum_domain_op__rcx 0xBF02000000010020
#define hypercall_enum_domain_op__set_rcx 0xBF02000000010021
#define hypercall_enum_domain_op__rdx 0xBF02000000010030
#define hypercall_enum_domain_op__set_rdx 0xBF02000000010031
#define hypercall_enum_domain_op__rbp 0xBF02000000010040
#define hypercall_enum_domain_op__set_rbp 0xBF02000000010041
#define hypercall_enum_domain_op__rsi 0xBF02000000010050
#define hypercall_enum_domain_op__set_rsi 0xBF02000000010051
#define hypercall_enum_domain_op__rdi 0xBF02000000010060
#define hypercall_enum_domain_op__set_rdi 0xBF02000000010061
#define hypercall_enum_domain_op__r08 0xBF02000000010070
#define hypercall_enum_domain_op__set_r08 0xBF02000000010071
#define hypercall_enum_domain_op__r09 0xBF02000000010080
#define hypercall_enum_domain_op__set_r09 0xBF02000000010081
#define hypercall_enum_domain_op__r10 0xBF02000000010090
#define hypercall_enum_domain_op__set_r10 0xBF02000000010091
#define hypercall_enum_domain_op__r11 0xBF020000000100A0
#define hypercall_enum_domain_op__set_r11 0xBF020000000100A1
#define hypercall_enum_domain_op__r12 0xBF020000000100B0
#define hypercall_enum_domain_op__set_r12 0xBF020000000100B1
#define hypercall_enum_domain_op__r13 0xBF020000000100C0
#define hypercall_enum_domain_op__set_r13 0xBF020000000100C1
#define hypercall_enum_domain_op__r14 0xBF020000000100D0
#define hypercall_enum_domain_op__set_r14 0xBF020000000100D1
#define hypercall_enum_domain_op__r15 0xBF020000000100E0
#define hypercall_enum_domain_op__set_r15 0xBF020000000100E1
#define hypercall_enum_domain_op__rip 0xBF020000000100F0
#define hypercall_enum_domain_op__set_rip 0xBF020000000100F1
#define hypercall_enum_domain_op__rsp 0xBF02000000010100
#define hypercall_enum_domain_op__set_rsp 0xBF02000000010101
#define hypercall_enum_domain_op__gdt_base 0xBF02000000010110
#define hypercall_enum_domain_op__set_gdt_base 0xBF02000000010111
#define hypercall_enum_domain_op__gdt_limit 0xBF02000000010120
#define hypercall_enum_domain_op__set_gdt_limit 0xBF02000000010121
#define hypercall_enum_domain_op__idt_base 0xBF02000000010130
#define hypercall_enum_domain_op__set_idt_base 0xBF02000000010131
#define hypercall_enum_domain_op__idt_limit 0xBF02000000010140
#define hypercall_enum_domain_op__set_idt_limit 0xBF02000000010141
#define hypercall_enum_domain_op__cr0 0xBF02000000010150
#define hypercall_enum_domain_op__set_cr0 0xBF02000000010151
#define hypercall_enum_domain_op__cr2 0xBF02000000010152
#define hypercall_enum_domain_op__set_cr2 0xBF02000000010153
#define hypercall_enum_domain_op__cr3 0xBF02000000010154
#define hypercall_enum_domain_op__set_cr3 0xBF02000000010155
#define hypercall_enum_domain_op__cr4 0xBF02000000010156
#define hypercall_enum_domain_op__set_cr4 0xBF02000000010157
#define hypercall_enum_domain_op__cr8 0xBF02000000010158
#define hypercall_enum_domain_op__set_cr8 0xBF02000000010159
#define hypercall_enum_domain_op__dr0 0xBF02000000010160
#define hypercall_enum_domain_op__set_dr0 0xBF02000000010161
#define hypercall_enum_domain_op__dr1 0xBF02000000010162
#define hypercall_enum_domain_op__set_dr1 0xBF02000000010163
#define hypercall_enum_domain_op__dr2 0xBF02000000010164
#define hypercall_enum_domain_op__set_dr2 0xBF02000000010165
#define hypercall_enum_domain_op__dr3 0xBF02000000010166
#define hypercall_enum_domain_op__set_dr3 0xBF02000000010167
#define hypercall_enum_domain_op__dr6 0xBF02000000010168
#define hypercall_enum_domain_op__set_dr6 0xBF02000000010169
#define hypercall_enum_domain_op__dr7 0xBF0200000001016A
#define hypercall_enum_domain_op__set_dr7 0xBF0200000001016B
#define hypercall_enum_domain_op__xcr0 0xBF02000000010170
#define hypercall_enum_domain_op__set_xcr0 0xBF02000000010171
#define hypercall_enum_domain_op__ia32_xss 0xBF02000000010172
#define hypercall_enum_domain_op__set_ia32_xss 0xBF02000000010173
#define hypercall_enum_domain_op__ia32_efer 0xBF02000000010180
#define hypercall_enum_domain_op__set_ia32_efer 0xBF02000000010181
#define hypercall_enum_domain_op__ia32_pat 0xBF02000000010190
#define hypercall_enum_domain_op__set_ia32_pat 0xBF02000000010191

#define hypercall_enum_domain_op__es_selector 0xBF02000000020000
#define hypercall_enum_domain_op__set_es_selector 0xBF02000000020001
#define hypercall_enum_domain_op__es_base 0xBF02000000020010
#define hypercall_enum_domain_op__set_es_base 0xBF02000000020011
#define hypercall_enum_domain_op__es_limit 0xBF02000000020020
#define hypercall_enum_domain_op__set_es_limit 0xBF02000000020021
#define hypercall_enum_domain_op__es_access_rights 0xBF02000000020030
#define hypercall_enum_domain_op__set_es_access_rights 0xBF02000000020031
#define hypercall_enum_domain_op__cs_selector 0xBF02000000020100
#define hypercall_enum_domain_op__set_cs_selector 0xBF02000000020101
#define hypercall_enum_domain_op__cs_base 0xBF02000000020110
#define hypercall_enum_domain_op__set_cs_base 0xBF02000000020111
#define hypercall_enum_domain_op__cs_limit 0xBF02000000020120
#define hypercall_enum_domain_op__set_cs_limit 0xBF02000000020121
#define hypercall_enum_domain_op__cs_access_rights 0xBF02000000020130
#define hypercall_enum_domain_op__set_cs_access_rights 0xBF02000000020131
#define hypercall_enum_domain_op__ss_selector 0xBF02000000020200
#define hypercall_enum_domain_op__set_ss_selector 0xBF02000000020201
#define hypercall_enum_domain_op__ss_base 0xBF02000000020210
#define hypercall_enum_domain_op__set_ss_base 0xBF02000000020211
#define hypercall_enum_domain_op__ss_limit 0xBF02000000020220
#define hypercall_enum_domain_op__set_ss_limit 0xBF02000000020221
#define hypercall_enum_domain_op__ss_access_rights 0xBF02000000020230
#define hypercall_enum_domain_op__set_ss_access_rights 0xBF02000000020231
#define hypercall_enum_domain_op__ds_selector 0xBF02000000020300
#define hypercall_enum_domain_op__set_ds_selector 0xBF02000000020301
#define hypercall_enum_domain_op__ds_base 0xBF02000000020310
#define hypercall_enum_domain_op__set_ds_base 0xBF02000000020311
#define hypercall_enum_domain_op__ds_limit 0xBF02000000020320
#define hypercall_enum_domain_op__set_ds_limit 0xBF02000000020321
#define hypercall_enum_domain_op__ds_access_rights 0xBF02000000020330
#define hypercall_enum_domain_op__set_ds_access_rights 0xBF02000000020331
#define hypercall_enum_domain_op__fs_selector 0xBF02000000020400
#define hypercall_enum_domain_op__set_fs_selector 0xBF02000000020401
#define hypercall_enum_domain_op__fs_base 0xBF02000000020410
#define hypercall_enum_domain_op__set_fs_base 0xBF02000000020411
#define hypercall_enum_domain_op__fs_limit 0xBF02000000020420
#define hypercall_enum_domain_op__set_fs_limit 0xBF02000000020421
#define hypercall_enum_domain_op__fs_access_rights 0xBF02000000020430
#define hypercall_enum_domain_op__set_fs_access_rights 0xBF02000000020431
#define hypercall_enum_domain_op__gs_selector 0xBF02000000020500
#define hypercall_enum_domain_op__set_gs_selector 0xBF02000000020501
#define hypercall_enum_domain_op__gs_base 0xBF02000000020510
#define hypercall_enum_domain_op__set_gs_base 0xBF02000000020511
#define hypercall_enum_domain_op__gs_limit 0xBF02000000020520
#define hypercall_enum_domain_op__set_gs_limit 0xBF02000000020521
#define hypercall_enum_domain_op__gs_access_rights 0xBF02000000020530
#define hypercall_enum_domain_op__set_gs_access_rights 0xBF02000000020531
#define hypercall_enum_domain_op__tr_selector 0xBF02000000020600
#define hypercall_enum_domain_op__set_tr_selector 0xBF02000000020601
#define hypercall_enum_domain_op__tr_base 0xBF02000000020610
#define hypercall_enum_domain_op__set_tr_base 0xBF02000000020611
#define hypercall_enum_domain_op__tr_limit 0xBF02000000020620
#define hypercall_enum_domain_op__set_tr_limit 0xBF02000000020621
#define hypercall_enum_domain_op__tr_access_rights 0xBF02000000020630
#define hypercall_enum_domain_op__set_tr_access_rights 0xBF02000000020631
#define hypercall_enum_domain_op__ldtr_selector 0xBF02000000020700
#define hypercall_enum_domain_op__set_ldtr_selector 0xBF02000000020701
#define hypercall_enum_domain_op__ldtr_base 0xBF02000000020710
#define hypercall_enum_domain_op__set_ldtr_base 0xBF02000000020711
#define hypercall_enum_domain_op__ldtr_limit 0xBF02000000020720
#define hypercall_enum_domain_op__set_ldtr_limit 0xBF02000000020721
#define hypercall_enum_domain_op__ldtr_access_rights 0xBF02000000020730
#define hypercall_enum_domain_op__set_ldtr_access_rights 0xBF02000000020731

#define UART_MAX_BUFFER 0x4000

static inline domainid_t
hypercall_domain_op__create_domain(void)
{
    return _vmcall(
               hypercall_enum_domain_op__create_domain,
               0,
               0,
               0
           );
}

static inline status_t
hypercall_domain_op__destroy_domain(domainid_t foreign_domainid)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__destroy_domain,
                       foreign_domainid,
                       0,
                       0
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__set_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__set_uart,
                       foreign_domainid,
                       uart,
                       0
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__set_pt_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__set_pt_uart,
                       foreign_domainid,
                       uart,
                       0
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline uint64_t
hypercall_domain_op__dump_uart(domainid_t domainid, char *buffer)
{
    return _vmcall(
               hypercall_enum_domain_op__dump_uart,
               domainid,
               bfrcast(uint64_t, buffer),
               0
           );
}

static inline status_t
hypercall_domain_op__share_page_r(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__share_page_r,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__share_page_rw(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__share_page_rw,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__share_page_rwe(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__share_page_rwe,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_r(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__donate_page_r,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_rw(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__donate_page_rw,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_rwe(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
                       hypercall_enum_domain_op__donate_page_rwe,
                       foreign_domainid,
                       gpa,
                       foreign_gpa
                   );

    return ret == 0 ? SUCCESS : FAILURE;
}

#define hypercall_domain_op__reg(reg)                                           \
    static inline uint64_t                                                      \
    hypercall_domain_op__ ## reg(domainid_t domainid)                           \
    {                                                                           \
        return _vmcall(                                                         \
                hypercall_enum_domain_op__## reg,                                   \
                domainid,                                                           \
                0,                                                                  \
                0                                                                   \
                      );                                                                      \
    }

#define hypercall_domain_op__set_reg(reg)                                       \
    static inline status_t                                                      \
    hypercall_domain_op__set_ ## reg(domainid_t domainid, uint64_t val)         \
    {                                                                           \
        status_t ret = _vmcall(                                                 \
                       hypercall_enum_domain_op__set_ ## reg,                              \
                       domainid,                                                           \
                       val,                                                                \
                       0                                                                   \
                              );                                                                      \
        \
        return ret == 0 ? SUCCESS : FAILURE;                                    \
    }

hypercall_domain_op__reg(rax)
hypercall_domain_op__set_reg(rax)
hypercall_domain_op__reg(rbx)
hypercall_domain_op__set_reg(rbx)
hypercall_domain_op__reg(rcx)
hypercall_domain_op__set_reg(rcx)
hypercall_domain_op__reg(rdx)
hypercall_domain_op__set_reg(rdx)
hypercall_domain_op__reg(rbp)
hypercall_domain_op__set_reg(rbp)
hypercall_domain_op__reg(rsi)
hypercall_domain_op__set_reg(rsi)
hypercall_domain_op__reg(rdi)
hypercall_domain_op__set_reg(rdi)
hypercall_domain_op__reg(r08)
hypercall_domain_op__set_reg(r08)
hypercall_domain_op__reg(r09)
hypercall_domain_op__set_reg(r09)
hypercall_domain_op__reg(r10)
hypercall_domain_op__set_reg(r10)
hypercall_domain_op__reg(r11)
hypercall_domain_op__set_reg(r11)
hypercall_domain_op__reg(r12)
hypercall_domain_op__set_reg(r12)
hypercall_domain_op__reg(r13)
hypercall_domain_op__set_reg(r13)
hypercall_domain_op__reg(r14)
hypercall_domain_op__set_reg(r14)
hypercall_domain_op__reg(r15)
hypercall_domain_op__set_reg(r15)
hypercall_domain_op__reg(rip)
hypercall_domain_op__set_reg(rip)
hypercall_domain_op__reg(rsp)
hypercall_domain_op__set_reg(rsp)
hypercall_domain_op__reg(gdt_base)
hypercall_domain_op__set_reg(gdt_base)
hypercall_domain_op__reg(gdt_limit)
hypercall_domain_op__set_reg(gdt_limit)
hypercall_domain_op__reg(idt_base)
hypercall_domain_op__set_reg(idt_base)
hypercall_domain_op__reg(idt_limit)
hypercall_domain_op__set_reg(idt_limit)
hypercall_domain_op__reg(cr0)
hypercall_domain_op__set_reg(cr0)
hypercall_domain_op__reg(cr2)
hypercall_domain_op__set_reg(cr2)
hypercall_domain_op__reg(cr3)
hypercall_domain_op__set_reg(cr3)
hypercall_domain_op__reg(cr4)
hypercall_domain_op__set_reg(cr4)
hypercall_domain_op__reg(cr8)
hypercall_domain_op__set_reg(cr8)
hypercall_domain_op__reg(dr0)
hypercall_domain_op__set_reg(dr0)
hypercall_domain_op__reg(dr1)
hypercall_domain_op__set_reg(dr1)
hypercall_domain_op__reg(dr2)
hypercall_domain_op__set_reg(dr2)
hypercall_domain_op__reg(dr3)
hypercall_domain_op__set_reg(dr3)
hypercall_domain_op__reg(dr6)
hypercall_domain_op__set_reg(dr6)
hypercall_domain_op__reg(dr7)
hypercall_domain_op__set_reg(dr7)
hypercall_domain_op__reg(xcr0)
hypercall_domain_op__set_reg(xcr0)
hypercall_domain_op__reg(ia32_xss)
hypercall_domain_op__set_reg(ia32_xss)
hypercall_domain_op__reg(ia32_efer)
hypercall_domain_op__set_reg(ia32_efer)
hypercall_domain_op__reg(ia32_pat)
hypercall_domain_op__set_reg(ia32_pat)

hypercall_domain_op__reg(es_selector)
hypercall_domain_op__set_reg(es_selector)
hypercall_domain_op__reg(es_base)
hypercall_domain_op__set_reg(es_base)
hypercall_domain_op__reg(es_limit)
hypercall_domain_op__set_reg(es_limit)
hypercall_domain_op__reg(es_access_rights)
hypercall_domain_op__set_reg(es_access_rights)
hypercall_domain_op__reg(cs_selector)
hypercall_domain_op__set_reg(cs_selector)
hypercall_domain_op__reg(cs_base)
hypercall_domain_op__set_reg(cs_base)
hypercall_domain_op__reg(cs_limit)
hypercall_domain_op__set_reg(cs_limit)
hypercall_domain_op__reg(cs_access_rights)
hypercall_domain_op__set_reg(cs_access_rights)
hypercall_domain_op__reg(ss_selector)
hypercall_domain_op__set_reg(ss_selector)
hypercall_domain_op__reg(ss_base)
hypercall_domain_op__set_reg(ss_base)
hypercall_domain_op__reg(ss_limit)
hypercall_domain_op__set_reg(ss_limit)
hypercall_domain_op__reg(ss_access_rights)
hypercall_domain_op__set_reg(ss_access_rights)
hypercall_domain_op__reg(ds_selector)
hypercall_domain_op__set_reg(ds_selector)
hypercall_domain_op__reg(ds_base)
hypercall_domain_op__set_reg(ds_base)
hypercall_domain_op__reg(ds_limit)
hypercall_domain_op__set_reg(ds_limit)
hypercall_domain_op__reg(ds_access_rights)
hypercall_domain_op__set_reg(ds_access_rights)
hypercall_domain_op__reg(fs_selector)
hypercall_domain_op__set_reg(fs_selector)
hypercall_domain_op__reg(fs_base)
hypercall_domain_op__set_reg(fs_base)
hypercall_domain_op__reg(fs_limit)
hypercall_domain_op__set_reg(fs_limit)
hypercall_domain_op__reg(fs_access_rights)
hypercall_domain_op__set_reg(fs_access_rights)
hypercall_domain_op__reg(gs_selector)
hypercall_domain_op__set_reg(gs_selector)
hypercall_domain_op__reg(gs_base)
hypercall_domain_op__set_reg(gs_base)
hypercall_domain_op__reg(gs_limit)
hypercall_domain_op__set_reg(gs_limit)
hypercall_domain_op__reg(gs_access_rights)
hypercall_domain_op__set_reg(gs_access_rights)
hypercall_domain_op__reg(tr_selector)
hypercall_domain_op__set_reg(tr_selector)
hypercall_domain_op__reg(tr_base)
hypercall_domain_op__set_reg(tr_base)
hypercall_domain_op__reg(tr_limit)
hypercall_domain_op__set_reg(tr_limit)
hypercall_domain_op__reg(tr_access_rights)
hypercall_domain_op__set_reg(tr_access_rights)
hypercall_domain_op__reg(ldtr_selector)
hypercall_domain_op__set_reg(ldtr_selector)
hypercall_domain_op__reg(ldtr_base)
hypercall_domain_op__set_reg(ldtr_base)
hypercall_domain_op__reg(ldtr_limit)
hypercall_domain_op__set_reg(ldtr_limit)
hypercall_domain_op__reg(ldtr_access_rights)
hypercall_domain_op__set_reg(ldtr_access_rights)

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_vcpu_op__create_vcpu 0xBF03000000000100
#define hypercall_enum_vcpu_op__kill_vcpu 0xBF03000000000101
#define hypercall_enum_vcpu_op__destroy_vcpu 0xBF03000000000102

static inline vcpuid_t
hypercall_vcpu_op__create_vcpu(domainid_t domainid)
{
    return _vmcall(
               hypercall_enum_vcpu_op__create_vcpu,
               domainid,
               0,
               0
           );
}

static inline status_t
hypercall_vcpu_op__kill_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
               hypercall_enum_vcpu_op__kill_vcpu,
               vcpuid,
               0,
               0
           );
}

static inline status_t
hypercall_vcpu_op__destroy_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
               hypercall_enum_vcpu_op__destroy_vcpu,
               vcpuid,
               0,
               0
           );
}

/* -------------------------------------------------------------------------- */
/* Virtual IRQs                                                               */
/* -------------------------------------------------------------------------- */

#define boxy_virq__vclock_event_handler 0xBF00000000000201

#define hypercall_enum_virq_op__set_hypervisor_callback_vector 0xBF10000000000100
#define hypercall_enum_virq_op__get_next_virq 0xBF10000000000101

static inline uint64_t
hypercall_virq_op__set_hypervisor_callback_vector(uint64_t vector)
{
    return _vmcall(
               hypercall_enum_virq_op__set_hypervisor_callback_vector, vector, 0, 0);
}

static inline uint64_t
hypercall_virq_op__get_next_virq(void)
{
    return _vmcall(
               hypercall_enum_virq_op__get_next_virq, 0, 0, 0);
}

/* -------------------------------------------------------------------------- */
/* Virtual Clock                                                              */
/* -------------------------------------------------------------------------- */

#define hypercall_enum_vclock_op__get_tsc_freq_khz 0xBF11000000000100
#define hypercall_enum_vclock_op__set_next_event 0xBF11000000000102
#define hypercall_enum_vclock_op__reset_host_wallclock 0xBF11000000000103
#define hypercall_enum_vclock_op__set_host_wallclock_rtc 0xBF11000000000104
#define hypercall_enum_vclock_op__set_host_wallclock_tsc 0xBF11000000000105
#define hypercall_enum_vclock_op__set_guest_wallclock_rtc 0xBF11000000000106
#define hypercall_enum_vclock_op__set_guest_wallclock_tsc 0xBF11000000000107
#define hypercall_enum_vclock_op__get_guest_wallclock 0xBF11000000000108

static inline uint64_t
hypercall_vclock_op__get_tsc_freq_khz(void)
{
    return _vmcall(
               hypercall_enum_vclock_op__get_tsc_freq_khz, 0, 0, 0);
}

static inline uint64_t
hypercall_vclock_op__set_next_event(uint64_t tsc_delta)
{
    return _vmcall(
               hypercall_enum_vclock_op__set_next_event, tsc_delta, 0, 0);
}

static inline status_t
hypercall_vclock_op__reset_host_wallclock(void)
{
    return _vmcall(
               hypercall_enum_vclock_op__reset_host_wallclock, 0, 0, 0
           );
}

static inline status_t
hypercall_vclock_op__set_host_wallclock_rtc(
    vcpuid_t vcpuid, int64_t sec, int64_t nsec)
{
    return _vmcall(
               hypercall_enum_vclock_op__set_host_wallclock_rtc,
               vcpuid,
               bfscast(uint64_t, sec),
               bfscast(uint64_t, nsec)
           );
}

static inline status_t
hypercall_vclock_op__set_host_wallclock_tsc(
    vcpuid_t vcpuid, uint64_t val)
{
    return _vmcall(
               hypercall_enum_vclock_op__set_host_wallclock_tsc,
               vcpuid,
               val,
               0
           );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_rtc(void)
{
    return _vmcall(
               hypercall_enum_vclock_op__set_guest_wallclock_rtc, 0, 0, 0
           );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_tsc(void)
{
    return _vmcall(
               hypercall_enum_vclock_op__set_guest_wallclock_tsc, 0, 0, 0
           );
}

static inline uint64_t
hypercall_vclock_op__get_guest_wallclock(
    int64_t *sec, long *nsec, uint64_t *tsc)
{
    uint64_t op = hypercall_enum_vclock_op__get_guest_wallclock;

    if (sec == 0 || nsec == 0 || tsc == 0) {
        return FAILURE;
    }

    return _vmcall4(
               &op, sec, nsec, tsc);
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
