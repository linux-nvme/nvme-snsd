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
#include "snsd_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

/* config all protocol value */
extern int any_protocol;

/* switched network infos list */
extern struct snsd_list sw_info_list;

/* directly connected network infos list */
extern struct snsd_list dc_info_list;

#ifdef __cplusplus
}
#endif  /* __cpluscplus */

namespace
{
    class snsd_cfg_ut : public ::testing::Test {
    protected:
        virtual void SetUp()
        {
            std::cout << "SetUp: snsd_cfg_ut." << std::endl;
        }

        virtual void TearDown()
        {
            std::cout << "TearDown: snsd_cfg_ut." << std::endl;
            GlobalMockObject::verify();
        }

    public:
        struct snsd_cfg_item_info bad_item_info;
    
        snsd_cfg_ut(void)
        {
            unsigned char bad_name[] = {"--data_digest"};
            unsigned char bad_value[] = {"bad_value"};
            char name[] = {"SW"};

            memset(&bad_item_info, 0, sizeof(struct snsd_cfg_item_info));

            bad_item_info.section_name = name;
	        memcpy(bad_item_info.name, bad_name, sizeof(bad_name));
            memcpy(bad_item_info.value, bad_value, sizeof(bad_value));
        }
    };
}

TEST_F(snsd_cfg_ut, cfg_init)
{
    int ret;
    ret = snsd_cfg_init();

    EXPECT_EQ(0, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, get_any_ip)
{
    enum SNSD_ANY_E ret;

	ret = snsd_get_any_ip();
    EXPECT_EQ(SNSD_ANY_BUTT, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, cfg_get_any_protocol)
{
    int ret;
    any_protocol = SNSD_PROTOCOL_ROCE;

	ret = snsd_get_any_protocol();
    EXPECT_EQ(SNSD_PROTOCOL_ROCE, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, cfg_get_net_cfg)
{
    struct snsd_list* ret = NULL;

	ret = snsd_get_net_cfg(SNSD_MODE_BUTT);
    EXPECT_EQ(NULL, ret);

    ret = snsd_get_net_cfg(SNSD_MODE_SW);
    EXPECT_EQ(&sw_info_list, ret);

    ret = snsd_get_net_cfg(SNSD_MODE_DC);
    EXPECT_EQ(&dc_info_list, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, get_base_hostnqn)
{
    char *ret;

	ret = snsd_get_base_hostnqn();
    EXPECT_EQ('\0', *ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, hostnqn_init)
{
    int ret;

	ret = snsd_hostnqn_init();
    EXPECT_EQ(0, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, get_base_info)
{
    struct snsd_base_cfg *ret;

	ret = snsd_get_base_info();
    EXPECT_EQ(&base_cfg, ret);

    sleep(1);   // wait 1 seconds to run at least one time.
}

TEST_F(snsd_cfg_ut, cfg_exit)
{
    snsd_cfg_exit();

    sleep(1);   // wait 1 seconds to run at least one time.
}