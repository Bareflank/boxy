//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/vm_properties_op.h>

namespace boxy::intel_x64
{

vm_properties_op_handler::vm_properties_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    if (vcpu->is_domU()) {
        return;
    }

    vcpu->add_vmcall_handler({&vm_properties_op_handler::dispatch, this});
}

void
vm_properties_op_handler::e820(vcpu *vcpu)
{
    try {
        auto vmid{vcpu->r11()};
        auto e820{vcpu->map_gpa_4k<mv_mdl_t>(vcpu->r13())};

        switch (vmid) {
            case MV_VMID_SELF:
                vmid = vcpu->domid();
                break;

            case MV_VMID_GLOBAL_STORE:
            case MV_VMID_ANY:
                vcpu->set_rax(MV_STATUS_INVALID_VMID_UNSUPPORTED_ANY);
                return;

            default:
                break;
        };

        auto &cached_e820 = get_domain(vmid)->e820_map();
        memcpy(e820.get(), &cached_e820, sizeof(mv_mdl_t));

        vcpu->set_rax(MV_STATUS_SUCCESS);
    }
    catchall({
        vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN);
    })
}

void
vm_properties_op_handler::set_e820(vcpu *vcpu)
{
    try {
        auto vmid{vcpu->r11()};
        auto e820{vcpu->map_gpa_4k<mv_mdl_t>(vcpu->r13())};

        switch (vmid) {
            case MV_VMID_SELF:
                vmid = vcpu->domid();
                break;

            case MV_VMID_GLOBAL_STORE:
            case MV_VMID_ANY:
                vcpu->set_rax(MV_STATUS_INVALID_VMID_UNSUPPORTED_ANY);
                return;

            default:
                break;
        };

        auto &cached_e820 = get_domain(vmid)->e820_map();
        memcpy(&cached_e820, e820.get(), sizeof(mv_mdl_t));

        vcpu->set_rax(MV_STATUS_SUCCESS);
    }
    catchall({
        vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN);
    })
}

bool
vm_properties_op_handler::dispatch(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VM_PROPERTIES_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VM_PROPERTIES_OP_E820_IDX_VAL:
            this->e820(vcpu);
            return true;

        case MV_VM_PROPERTIES_OP_SET_E820_IDX_VAL:
            this->set_e820(vcpu);
            return true;

        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
