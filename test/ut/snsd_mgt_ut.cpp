/*
 * BSD 3-Clause License
 * 
 * Copyright (c) [2020], [Huawei Technologies Co., Ltd.]
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "gtest/gtest.h"
#include <mockcpp/mockcpp.hpp>
#include "snsd.h"
#include "snsd_mgt.h"
#include "snsd_switch.h"
#include "snsd_direct.h"

namespace
{
    class snsd_mgt_ut : public ::testing::Test {
    protected:
        virtual void SetUp()
        {
            std::cout << "SetUp: snsd_mgt_ut." << std::endl;
        }

        virtual void TearDown()
        {
            std::cout << "TearDown: snsd_mgt_ut." << std::endl;
            GlobalMockObject::verify();
        }
    };
}

TEST_F(snsd_mgt_ut, mgt_prot_handle)
{
    unsigned int poll_count = SWITCH_POLL_INTEVAL;
    int ret = 0;
    LIST_HEAD(direct_port_head);
    LIST_HEAD(switch_port_head);

	switch_port_handle(&switch_port_head, poll_count);
    direct_port_handle(&direct_port_head, poll_count);

    snsd_free_net_list(&direct_port_head);
    snsd_free_net_list(&switch_port_head);
    EXPECT_EQ(0, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}
