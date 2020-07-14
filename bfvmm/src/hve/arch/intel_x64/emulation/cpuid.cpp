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
#include <hve/arch/intel_x64/emulation/cpuid.h>

#define EMULATE_CPUID(a,b)                                                     \
    m_vcpu->add_cpuid_emulator(a, {&cpuid_handler::b, this});

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    EMULATE_CPUID(0x00000001, handle_0x00000001);

    EMULATE_CPUID(0x40000000, handle_0x40000000);
    EMULATE_CPUID(0x40000200, handle_0x40000200);
    EMULATE_CPUID(0x40000201, handle_0x40000201);
    EMULATE_CPUID(0x40000202, handle_0x40000202);

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->enable_cpuid_whitelisting();

    EMULATE_CPUID(0x00000000, handle_0x00000000);
    EMULATE_CPUID(0x00000002, handle_0x00000002);
    EMULATE_CPUID(0x00000004, handle_0x00000004);
    EMULATE_CPUID(0x00000006, handle_0x00000006);
    EMULATE_CPUID(0x00000007, handle_0x00000007);
    EMULATE_CPUID(0x0000000A, handle_0x0000000A);
    EMULATE_CPUID(0x0000000B, handle_0x0000000B);
    EMULATE_CPUID(0x0000000D, handle_0x0000000D);
    EMULATE_CPUID(0x0000000F, handle_0x0000000F);
    EMULATE_CPUID(0x00000010, handle_0x00000010);
    EMULATE_CPUID(0x80000000, handle_0x80000000);
    EMULATE_CPUID(0x80000001, handle_0x80000001);
    EMULATE_CPUID(0x80000002, handle_0x80000002);
    EMULATE_CPUID(0x80000003, handle_0x80000003);
    EMULATE_CPUID(0x80000004, handle_0x80000004);
    EMULATE_CPUID(0x80000007, handle_0x80000007);
    EMULATE_CPUID(0x80000008, handle_0x80000008);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle_0x00000000(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000001(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    if (m_vcpu->is_dom0()) {
        vcpu->set_rcx(vcpu->rcx() | 0x80000000);
        return vcpu->advance();
    }

    vcpu->set_rcx((vcpu->rcx() & 0x61FC3203) | 0x80000000);
    vcpu->set_rdx(vcpu->rdx() & 0x1FCBFBFB);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000002(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000004(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(vcpu->rax() & 0x000003FF);
    vcpu->set_rax(vcpu->rax() | 0x04004000);
    vcpu->set_rdx(vcpu->rdx() & 0x00000007);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000006(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000007(vcpu_t *vcpu)
{
    if (vcpu->gr2() != 0) {
        return vcpu->advance();
    }

    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(vcpu->rbx() & 0x019C23D9);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000A(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(vcpu->rbx() & 0x0000007F);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000B(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000D(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000F(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000010(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000000(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000001(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rbx(0);
    vcpu->set_rcx(vcpu->rcx() & 0x00000121);
    vcpu->set_rdx(vcpu->rdx() & 0x24100800);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000002(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000003(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000004(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000007(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rcx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000008(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(vcpu->rax() & 0x0000FFFF);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x40000000(vcpu_t *vcpu)
{
    vcpu->set_rax(MV_CPUID_MIN_LEAF_VAL);
    vcpu->set_rdx(0x0);
    vcpu->set_rdx(0x0);
    vcpu->set_rdx(0x0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x40000200(vcpu_t *vcpu)
{
    vcpu->set_rax(0x0);
    vcpu->set_rbx(MV_CPUID_VENDOR_ID1_VAL);
    vcpu->set_rcx(MV_CPUID_VENDOR_ID2_VAL);
    vcpu->set_rdx(0x0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x40000201(vcpu_t *vcpu)
{
    vcpu->set_rax(MV_CPUID_SPEC_ID1);
    vcpu->set_rbx(0x0);
    vcpu->set_rcx(0x0);
    vcpu->set_rdx(0x0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x40000202(vcpu_t *vcpu)
{
    vcpu->set_rax(0x0);
    vcpu->set_rbx(0x0);
    vcpu->set_rcx(0x0);
    vcpu->set_rdx(0x0);

    return vcpu->advance();
}

}
