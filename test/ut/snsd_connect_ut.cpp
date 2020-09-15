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
#include "snsd_connect.h"
#include "snsd_conn_peon.h"

namespace
{
    class snsd_connect_ut : public ::testing::Test {
    protected:
        virtual void SetUp()
        {
            std::cout << "SetUp: snsd_connect_ut." << std::endl;
        }

        virtual void TearDown()
        {
            std::cout << "TearDown: snsd_connect_ut." << std::endl;
            GlobalMockObject::verify();
        }

    public:
        unsigned char bad_traddr[IPV6_ADDR_LENGTH];
        unsigned char bad_host_traddr[IPV6_ADDR_LENGTH];
        unsigned char good_traddr[IPV6_ADDR_LENGTH];
        unsigned char good_host_traddr[IPV6_ADDR_LENGTH];
    
        snsd_connect_ut(void)
        {
            unsigned char traddr1[] = {10, 10, 10, 2};
            unsigned char host_traddr1[] = {10, 10, 10, 1};
            unsigned char traddr2[] = {2, 30, 10, 2};
            unsigned char host_traddr2[] = {2, 30, 10, 1};

            memset(bad_traddr, 0, sizeof(bad_traddr));
            memset(bad_host_traddr, 0, sizeof(bad_host_traddr));
            memset(good_traddr, 0, sizeof(good_traddr));
            memset(good_host_traddr, 0, sizeof(good_host_traddr));
            
            memcpy(bad_traddr, traddr1, sizeof(traddr1));
	        memcpy(bad_host_traddr, host_traddr1, sizeof(host_traddr1));
            memcpy(good_traddr, traddr2, sizeof(traddr2));
	        memcpy(good_host_traddr, host_traddr2, sizeof(host_traddr2));
        }
    };
}

TEST_F(snsd_connect_ut, connect_with_bad_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, bad_traddr, sizeof(bad_traddr));
	memcpy(param.host_traddr, bad_host_traddr, sizeof(bad_host_traddr));

	ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_with_good_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

    // Add a new device
	ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.

    // Add a existed device
    ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_with_read_fail)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

    MOCKER(read)
    .stubs()
    .will(returnValue(-1));

    // Add a new device
	ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_with_unknown_protocol)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_BUTT;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

	ret = snsd_connect(&param);
    EXPECT_EQ(-EINVAL, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_with_error_address_family)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = 0;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

	ret = snsd_connect(&param);
    EXPECT_EQ(-EINVAL, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_with_alloc_task_fail)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

    MOCKER(calloc)
    .stubs()
    .will(returnValue(static_cast<void *>(NULL)));

	ret = snsd_connect(&param);
    EXPECT_EQ(-ENOMEM, ret);
}

TEST_F(snsd_connect_ut, connect_with_fail_scandir)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

    MOCKER(scandir)
    .stubs()
    .will(returnValue(-1));

    ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run task.
}

TEST_F(snsd_connect_ut, disconnect_with_good_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

	ret = snsd_disconnect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, disconnect_with_bad_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, bad_traddr, sizeof(bad_traddr));
	memcpy(param.host_traddr, bad_host_traddr, sizeof(bad_host_traddr));

	ret = snsd_disconnect(&param);
    EXPECT_EQ(0, ret);

    sleep(5);   // wait 5 seconds to run at least one time.
}

TEST_F(snsd_connect_ut, connect_and_disconnect_with_good_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

	ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.

    ret = snsd_disconnect(&param);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.
}

TEST_F(snsd_connect_ut, disconnect_batch_with_good_address)
{
    int ret;

    ret = snsd_disconnect_by_host_traddr(AF_INET, good_host_traddr);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.
}

TEST_F(snsd_connect_ut, disconnect_batch_with_error_address_family)
{
    int ret;

    ret = snsd_disconnect_by_host_traddr(0, good_host_traddr);
    EXPECT_EQ(-EINVAL, ret);

    sleep(2);   // wait 2 seconds.
}

TEST_F(snsd_connect_ut, disconnect_batch_with_scandir_fail)
{
    int ret;

    MOCKER(scandir)
    .stubs()
    .will(returnValue(-1));

    ret = snsd_disconnect_by_host_traddr(AF_INET, good_host_traddr);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.
}

TEST_F(snsd_connect_ut, connect_and_disconnect_batch_with_good_address)
{
    int ret;
    struct snsd_connect_param param;

	memset(&param, 0, sizeof(struct snsd_connect_param));
	param.protocol = SNSD_PROTOCOL_ROCE;
    param.family   = AF_INET;
    memcpy(param.traddr, good_traddr, sizeof(good_traddr));
	memcpy(param.host_traddr, good_host_traddr, sizeof(good_host_traddr));

	ret = snsd_connect(&param);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.

    ret = snsd_disconnect_by_host_traddr(AF_INET, good_host_traddr);
    EXPECT_EQ(0, ret);

    sleep(2);   // wait 2 seconds.
}
