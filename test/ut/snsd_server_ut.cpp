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
#include "snsd_server.h"
#include "snsd_mgt.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

extern int snsd_get_server_sock(struct snsd_port_related_info *port);
extern int snsd_bind_sock(int sock_fd, struct snsd_port_related_info *port);
extern int snsd_set_sock_options(int sock_fd, int ifindex);
extern void snsd_client_notify(int fd);
extern void snsd_int_drop_msg_cnt(void);
extern unsigned long long snsd_get_drop_msg_cnt(void);
static void ut_server_instance_init(void);
static void ut_server_instance_exit(void);
static void ut_server_init_obj(void);
static void ut_case_init_obj(void);
int snsd_connect(struct snsd_connect_param *param);
int snsd_disconnect(struct snsd_connect_param *param);

#ifdef __cplusplus
}
#endif /* __cpluscplus */
struct msg_cnt {
    int connect_msg_cnt;
    int disconnect_msg_cnt;
    int ack_msg_cnt;
};
struct server_test_object {
    int sock;
    char name[IFNAMSIZ];
    unsigned char local_ip[SNSD_MAX_IP_PHYPORT][IPV4_ADDR_LENGTH];
    unsigned char remote_ip[IPV4_ADDR_LENGTH];
    unsigned char local_mac[MAC_LENGTH];
    unsigned char remote_mac[ETH_ALEN];
    char nqn[SNSD_NQN_MAX_LEN];
    unsigned short eth_type;
    unsigned char ver;
    unsigned char mrp_mac[ETH_ALEN];
    int tlv_inject;
    enum nt_msg_notify_type type;
    struct msg_cnt cnt;
} test_obj;
struct snsd_nt_msg_info my_test_msg;
unsigned char test_invalid_ip[] = {192, 168, 0, 111};
namespace {
    class snsd_server_ut : public ::testing::Test {
    protected:
        static void SetUpTestCase()
        {
            ut_server_init_obj();
            ut_server_instance_init();
        }
        static void TearDownTestCase()
        {
            ut_server_instance_exit();
        }
        virtual void SetUp()
        {
            std::cout << "SetUp: snsd_server_ut." << std::endl;
            ut_case_init_obj();
        }
        virtual void TearDown()
        {
            std::cout << "TearDown: snsd_server_ut." << std::endl;
            GlobalMockObject::verify();
        }
    };
}

static void ut_server_build_multi_ip(void)
{
    unsigned char local_ip[] = {192, 168, 0, 1};
    for (int i = 0; i < SNSD_MAX_IP_PHYPORT; i++) {
        local_ip[3] += i;
        memcpy(test_obj.local_ip[i], local_ip, IPV4_ADDR_LENGTH);
    }
}

static void ut_server_init_obj(void)
{
    unsigned char remote_ip[] = {127, 0, 0, 1};
    unsigned char local_mac[MAC_LENGTH] = {0x0, 0x3, 0x88, 0x55, 0x0, 0x38};
    unsigned char remote_mac[ETH_ALEN] = {0x50, 0x6b, 0x4b, 0xef, 0xcb, 0x46};
    char nqn[] = "nqn.2014-08.com.huawei:nvme:nvm-subsystem-sn";

    memset(&test_obj, 0, sizeof(test_obj));
    test_obj.sock = -1;
    strncpy(test_obj.name, "eth0", IFNAMSIZ);
    memcpy(test_obj.remote_ip, remote_ip, IPV4_ADDR_LENGTH);
    memcpy(test_obj.local_mac, local_mac, MAC_LENGTH);
    memcpy(test_obj.remote_mac, remote_mac, MAC_LENGTH);
    strncpy(test_obj.nqn, nqn, sizeof(test_obj.nqn));
    ut_server_build_multi_ip();
}

static void ut_case_init_obj(void)
{
    unsigned char mrp_mac[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0d};
    test_obj.cnt.connect_msg_cnt = 0;
    test_obj.cnt.disconnect_msg_cnt = 0;
    test_obj.cnt.ack_msg_cnt = 0;
    test_obj.eth_type = ETH_NTS_TYPE;
    test_obj.ver = SNSD_NTF_VER;
    for (int i = 0; i < ETH_ALEN; i++) {
        test_obj.mrp_mac[i] = mrp_mac[i];
    }
    test_obj.tlv_inject = 0;
    snsd_int_drop_msg_cnt();
}

static int ut_server_create_instance(void)
{
    struct snsd_port_related_info port;
    int ret;

    memset((void *)&port, 0, sizeof(port));
    strncpy(port.name, test_obj.name, IFNAMSIZ);
    memcpy(port.mac, test_obj.local_mac, sizeof(test_obj.local_mac));
    port.ifindex = -1;
    ret = snsd_get_server_sock(&port);

    return ret;
}

static void ut_server_instance_init(void)
{
    int sock_id;

    MOCKER(snsd_bind_sock)
        .stubs()
        .will(returnValue(0));
    MOCKER(snsd_set_sock_options)
        .stubs()
        .will(returnValue(0));

    sock_id = ut_server_create_instance();
    EXPECT_GE(sock_id, 0);
    test_obj.sock = sock_id;
}

static void ut_server_instance_exit(void)
{
    int sock_id = test_obj.sock;
    int ret;
    struct snsd_port_related_info port_info;
    ASSERT_TRUE(test_obj.sock >= 0);

    memset(&port_info, 0, sizeof(port_info));
    memcpy(port_info.ip, test_obj.local_ip[0], IPV4_ADDR_LENGTH);

    ret = snsd_update_sock_ip(sock_id, &port_info, SNSD_UPDATE_REMOVE_IP);
    snsd_sock_close(sock_id);
    EXPECT_EQ(ret, 0);
    test_obj.sock = -1;
}

static void ut_msg_header_err_inject(struct snsd_nt_msg_info *msg)
{
    msg->eth_hdr.h_proto = htons(test_obj.eth_type);
    msg->nt_header.ver = test_obj.ver;
    for (int i = 0; i < ETH_ALEN; i++) {
        msg->eth_hdr.h_dest[i] = test_obj.mrp_mac[i];
    }
}

static void ut_msg_tlv_err_inject(struct snsd_nt_msg_info *msg)
{
   msg->nt_header.tlv_len += test_obj.tlv_inject;
}

static void ut_encode_eth_header(struct snsd_nt_msg_info *msg, unsigned char *local_mac)
{
    for (int i = 0; i < ETH_ALEN; i++) {
        msg->eth_hdr.h_dest[i] = test_obj.mrp_mac[i];
    }

    memcpy(msg->eth_hdr.h_source, local_mac, ETH_ALEN);
    msg->eth_hdr.h_proto = htons(ETH_NTS_TYPE);
}

static void ut_encode_msg_header(struct snsd_nt_msg_info *msg)
{
    msg->nt_header.ver = SNSD_NTF_VER;
    msg->nt_header.tlv_len = 0;
    msg->nt_header.reserved0 = 0;
    msg->nt_header.reserved1 = 0;
}

static void ut_encode_ip_tlv(struct snsd_nt_msg_info *msg, struct tlv_info *tlv,
    struct ipv4_pair *ip)
{
    tlv->nt_msg.ip_tlv.ipv4.src.tl.type = NOTIFY_SUB_TLV1_SRC_IPV4;
    tlv->nt_msg.ip_tlv.ipv4.src.tl.len = IPV4_ADDR_LENGTH;
    NT_TLV_HTONS(tlv->nt_msg.ip_tlv.ipv4.src.tl.len);
    memcpy(tlv->nt_msg.ip_tlv.ipv4.src.ip, ip->src_ip, IPV4_ADDR_LENGTH);
    tlv->nt_msg.ip_tlv.ipv4.dst.tl.type = NOTIFY_SUB_TLV2_DST_IPV4;
    tlv->nt_msg.ip_tlv.ipv4.dst.tl.len = IPV4_ADDR_LENGTH;
    NT_TLV_HTONS(tlv->nt_msg.ip_tlv.ipv4.dst.tl.len);
    memcpy(tlv->nt_msg.ip_tlv.ipv4.dst.ip, ip->dst_ip, IPV4_ADDR_LENGTH);
    
    memcpy(&msg->offset[msg->nt_header.tlv_len], 
        &tlv->nt_msg.ip_tlv, sizeof(tlv->nt_msg.ip_tlv.ipv4));
    msg->nt_header.tlv_len += sizeof(tlv->nt_msg.ip_tlv.ipv4);
}

static void ut_encode_seq_tlv(struct snsd_nt_msg_info *msg, struct tlv_info *tlv,
    unsigned int seq_num)
{
    tlv->nt_msg.seq_num_tlv.tl.type = NOTIFY_SUB_TLV5_SEQ;
    tlv->nt_msg.seq_num_tlv.tl.len = sizeof(unsigned int);
    NT_TLV_HTONS(tlv->nt_msg.seq_num_tlv.tl.len);
    tlv->nt_msg.seq_num_tlv.seq_num = seq_num;
    memcpy(&msg->offset[msg->nt_header.tlv_len], 
        &tlv->nt_msg.seq_num_tlv, sizeof(tlv->nt_msg.seq_num_tlv));
    msg->nt_header.tlv_len += sizeof(tlv->nt_msg.seq_num_tlv);
}

static void ut_encode_state_tlv(struct snsd_nt_msg_info *msg, struct tlv_info *tlv, 
    char state)
{
    tlv->nt_msg.state_tlv.tl.type = NOTIFY_SUB_TLV6_STATE;
    tlv->nt_msg.state_tlv.tl.len = sizeof(char);
    NT_TLV_HTONS(tlv->nt_msg.state_tlv.tl.len);
    tlv->nt_msg.state_tlv.state = state;
    memcpy(&msg->offset[msg->nt_header.tlv_len], 
        &tlv->nt_msg.state_tlv, sizeof(tlv->nt_msg.state_tlv));
    msg->nt_header.tlv_len += sizeof(tlv->nt_msg.state_tlv);
}

static void ut_encode_nt_reason_tlv(struct snsd_nt_msg_info *msg, struct tlv_info *tlv,
    unsigned char nt_reason)
{
    tlv->nt_msg.nt_reason_tlv.tl.type = NOTIFY_SUB_TLV7_REASON;
    tlv->nt_msg.nt_reason_tlv.tl.len = sizeof(char);
    NT_TLV_HTONS(tlv->nt_msg.nt_reason_tlv.tl.len);
    tlv->nt_msg.nt_reason_tlv.nt_reason = nt_reason; 
    memcpy(&msg->offset[msg->nt_header.tlv_len], 
        &tlv->nt_msg.nt_reason_tlv, sizeof(tlv->nt_msg.nt_reason_tlv));
    msg->nt_header.tlv_len += sizeof(tlv->nt_msg.nt_reason_tlv);
}

static void ut_encode_ad_tlv(struct snsd_nt_msg_info *msg, struct tlv_info *tlv, 
    char *nqn)
{
    tlv->nt_msg.ad_info_tlv.tl.type = NOTIFY_SUB_TLV8_AD;
    tlv->nt_msg.ad_info_tlv.tl.len = strlen(nqn) + 7; /* 7 ad_info len except nqn */
    NT_TLV_HTONS(tlv->nt_msg.ad_info_tlv.tl.len);
    tlv->nt_msg.ad_info_tlv.ad_info.role_type = SNSD_SERVER;
    tlv->nt_msg.ad_info_tlv.ad_info.proto_type = SNSD_PROTOCOL_ROCE;
    tlv->nt_msg.ad_info_tlv.ad_info.reserved = 0;
    tlv->nt_msg.ad_info_tlv.ad_info.proto_port = 4420; /* 4420 RDMA Portid */
    NT_TLV_HTONS(tlv->nt_msg.ad_info_tlv.ad_info.proto_port);
    tlv->nt_msg.ad_info_tlv.ad_info.nqn_length = strlen(nqn);
    strncpy((char *)tlv->nt_msg.ad_info_tlv.ad_info.nqn, nqn, SNSD_NQN_MAX_LEN);
    tlv->nt_msg.ad_info_tlv.ad_info.nqn[SNSD_NQN_MAX_LEN - 1] = '\0';
    memcpy(&msg->offset[msg->nt_header.tlv_len], 
        &tlv->nt_msg.ad_info_tlv, strlen(nqn) + 10); /* 10 ad_info + tl len except nqn */
    msg->nt_header.tlv_len += strlen(nqn) + 10; /* 10 ad_info + tl len except nqn */
}

static void ut_encode_msg(struct snsd_nt_msg_info *msg, void *tlv_t, struct ipv4_pair *ip, 
    char state, char *nqn)
{
#define TL_LEN 3
    struct tlv_info *tlv = (struct tlv_info *)tlv_t;

    tlv->type = SNSD_TLV_FORMAT_STRUCT | 0x1; 
    tlv->len = sizeof(tlv->nt_msg.ip_tlv.ipv4) + 
        sizeof(tlv->nt_msg.seq_num_tlv) + 
        sizeof(tlv->nt_msg.state_tlv) + 
        sizeof(tlv->nt_msg.nt_reason_tlv) + 
        sizeof(tlv->nt_msg.ad_info_tlv) -
        SNSD_NQN_MAX_LEN +
        strlen(nqn); 
    NT_TLV_HTONS(tlv->len);
    memcpy(&msg->offset[msg->nt_header.tlv_len], tlv, TL_LEN);
    msg->nt_header.tlv_len += TL_LEN;

    ut_encode_ip_tlv(msg, tlv, ip);
    /* 0x12345678 test seq num */
    ut_encode_seq_tlv(msg, tlv, 0x12345678);
    /* 1 test notify reason */
    ut_encode_state_tlv(msg, tlv, state);
    ut_encode_nt_reason_tlv(msg, tlv, 1);
    ut_encode_ad_tlv(msg, tlv, nqn);
    return;
}

static ssize_t recvmsg_invalid_ip_stub(int sockfd, struct msghdr *msg, int flags)
{
    struct ipv4_pair ip;
    struct tlv_info nt_tlv;
    int msg_len;
    memcpy(ip.dst_ip, test_invalid_ip, IPV4_ADDR_LENGTH);
    memcpy(ip.src_ip, test_obj.remote_ip, IPV4_ADDR_LENGTH);

    memset(&my_test_msg, 0, sizeof(my_test_msg));
    ut_encode_eth_header(&my_test_msg, test_obj.remote_mac);
    ut_encode_msg_header(&my_test_msg);
    ut_msg_header_err_inject(&my_test_msg);
    ut_encode_msg(&my_test_msg, (void *)&nt_tlv, &ip, 
        test_obj.type, test_obj.nqn);

    msg_len = sizeof(struct ethhdr) + 
        sizeof(nt_msg_header) + 
        my_test_msg.nt_header.tlv_len;
    
    ut_msg_tlv_err_inject(&my_test_msg);
    NT_TLV_HTONS(my_test_msg.nt_header.tlv_len);

    memcpy(msg->msg_iov[0].iov_base, &my_test_msg, msg_len);
    return msg_len;
}

static ssize_t recvmsg_single_nt_stub(int sockfd, struct msghdr *msg, int flags)
{
    struct ipv4_pair ip;
    struct tlv_info nt_tlv;
    int msg_len;

    memcpy(ip.dst_ip, test_obj.local_ip[0], IPV4_ADDR_LENGTH);
    memcpy(ip.src_ip, test_obj.remote_ip, IPV4_ADDR_LENGTH);

    memset(&my_test_msg, 0, sizeof(my_test_msg));
    ut_encode_eth_header(&my_test_msg, test_obj.remote_mac);
    ut_encode_msg_header(&my_test_msg);
    ut_msg_header_err_inject(&my_test_msg);
    ut_encode_msg(&my_test_msg, (void *)&nt_tlv, &ip, 
        test_obj.type, test_obj.nqn);

    msg_len = sizeof(struct ethhdr) + 
        sizeof(nt_msg_header) + 
        my_test_msg.nt_header.tlv_len;
    
    ut_msg_tlv_err_inject(&my_test_msg);
    NT_TLV_HTONS(my_test_msg.nt_header.tlv_len);

    memcpy(msg->msg_iov[0].iov_base, &my_test_msg, msg_len);
    return msg_len;
}

static ssize_t recvmsg_multi_nt_stub(int sockfd, struct msghdr *msg, int flags)
{
    struct ipv4_pair ip;
    struct tlv_info nt_tlv;
    int msg_len;

    memcpy(ip.dst_ip, test_obj.local_ip[0], IPV4_ADDR_LENGTH);
    memcpy(ip.src_ip, test_obj.remote_ip, IPV4_ADDR_LENGTH);

    memset(&my_test_msg, 0, sizeof(my_test_msg));
    ut_encode_eth_header(&my_test_msg, test_obj.remote_mac);
    ut_encode_msg_header(&my_test_msg);
    ut_encode_msg(&my_test_msg, (void *)&nt_tlv, &ip, 
        NOTIFY_HOST_INACTIVE, test_obj.nqn);
    ut_encode_msg(&my_test_msg, (void *)&nt_tlv, &ip, 
        NOTIFY_HOST_ACTIVE, test_obj.nqn);

    msg_len = sizeof(struct ethhdr) + 
        sizeof(nt_msg_header) + 
        my_test_msg.nt_header.tlv_len;
    NT_TLV_HTONS(my_test_msg.nt_header.tlv_len);

    memcpy(msg->msg_iov[0].iov_base, &my_test_msg, msg_len);
    return msg_len;
}
static int snsd_connect_stub(struct snsd_connect_param *param)
{
    test_obj.cnt.connect_msg_cnt++;
    return 0;
}

static int snsd_disconnect_stub(struct snsd_connect_param *param)
{
    test_obj.cnt.disconnect_msg_cnt++;
    return 0;
}

static char snsd_ack_tlv_type(char *buf)
{
    return *(char*)buf;
}

static unsigned short snsd_ack_tlv_len(char *buf)
{
    unsigned short len = *(unsigned short*)buf;
    return ntohs(len);
}

static int snsd_decode_ack_tlv(char *buf, unsigned int len)
{
    unsigned char root_type;
    unsigned short root_len;
    unsigned int root_pos = 0;
    int error = 0;

    do {
        if ((root_pos + SNSD_TLV_TAG_SIZE) > len) {
            break;
        }
        root_type = snsd_ack_tlv_type(buf + root_pos);
        if (!(root_type & SNSD_TLV_FORMAT_STRUCT) || 
            ((root_type & SNSD_MSG_NOTIFY_MASK) != SNSD_MSG_NOTIFY_ACK_TYPE)) {
            error = -1;
            break;
        }
        root_pos += SNSD_TLV_TAG_SIZE;
        if ((root_pos + SNSD_TLV_LEN_SIZE) > len) {
            error = -1;
            break;
        }
        root_len = snsd_ack_tlv_len(buf + root_pos);
        root_pos += SNSD_TLV_LEN_SIZE;
        if ((root_pos + root_len) > len) {
            error = -1;
            break;
        }
        root_pos += root_len;
    } while (root_pos <= len);

    return error;
}

static int snsd_get_ack_msg_header(char *buf, size_t len, unsigned int *tlv_len)
{
    nt_msg_header msg_headr;
    struct ethhdr eth_hdr;
    unsigned short tlv_sum_len;
    const unsigned char dest[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0d};

    if (len < (sizeof(nt_msg_header) + sizeof(struct ethhdr)) || 
        (len > SNSD_MAX_BUFFER_LEN)) {
        return -EACCES;
    }
    memcpy(&eth_hdr, buf, sizeof(struct ethhdr));
    if (ntohs(eth_hdr.h_proto) != ETH_NTS_TYPE) {
        return -EACCES;
    }
    if (!MAC_CMP_EQUAL(eth_hdr.h_dest, dest)) {
        return -EACCES;
    }
    memcpy(&msg_headr, buf + sizeof(struct ethhdr), sizeof(msg_headr));
    if (msg_headr.ver > SNSD_NTF_VER) {
        return -EACCES;
    }
    tlv_sum_len = ntohs(msg_headr.tlv_len);
    if ((tlv_sum_len == 0) || 
        (tlv_sum_len > len - (sizeof(nt_msg_header) + sizeof(struct ethhdr)))) {
        return -EACCES;
    }

    *tlv_len = tlv_sum_len;
    return 0;
}

static ssize_t sendto_stub(int sockfd, const void *buf, size_t len, int flags, 
    const struct sockaddr *dest_addr,socklen_t addrlen)
{
    unsigned int tlv_len = 0;
    unsigned int offset = 0;
    int result;

    result = snsd_get_ack_msg_header((char*)buf, len, &tlv_len);
    EXPECT_EQ(result, 0);

    offset = sizeof(nt_msg_header) + sizeof(struct ethhdr);
    result = snsd_decode_ack_tlv((char*)buf + offset, tlv_len);
    EXPECT_EQ(result, 0);

    if (result == 0) {
        test_obj.cnt.ack_msg_cnt++;
        return len;
    } else {
        return 0;
    }
}

void snsd_ut_common_stub(void)
{
    MOCKER(sendto)
        .stubs()
        .will(invoke(sendto_stub));
    MOCKER(snsd_connect)
        .stubs()
        .will(invoke(snsd_connect_stub));
    MOCKER(snsd_disconnect)
        .stubs()
        .will(invoke(snsd_disconnect_stub));
}

TEST_F(snsd_server_ut, case1_server_update_ip)
{
    struct snsd_port_related_info port_info;
    int ret;
    ASSERT_TRUE(test_obj.sock >= 0);

    memset(&port_info, 0, sizeof(port_info));
    memcpy(port_info.ip, test_obj.local_ip[0], IPV4_ADDR_LENGTH);

    ret = snsd_update_sock_ip(test_obj.sock, &port_info, SNSD_UPDATE_ADD_IP);
    EXPECT_EQ(ret, 0);
}

TEST_F(snsd_server_ut, case2_server_notify_connect)
{
    ASSERT_TRUE(test_obj.sock >= 0);

    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    test_obj.type = NOTIFY_HOST_ACTIVE;
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 1);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 1);
}

TEST_F(snsd_server_ut, case3_server_notify_disconnect)
{
    ASSERT_TRUE(test_obj.sock >= 0);

    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    test_obj.type = NOTIFY_HOST_INACTIVE;
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 1);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 1);
}

TEST_F(snsd_server_ut, case4_server_multi_notify)
{
    ASSERT_TRUE(test_obj.sock >= 0);

    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_multi_nt_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 1);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 1);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 1);
}

TEST_F(snsd_server_ut, case5_server_invalid_msg_type)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    test_obj.eth_type = 0x55aa;
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}

TEST_F(snsd_server_ut, case6_server_invalid_dst_mac)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    test_obj.mrp_mac[3] = 0x2;
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}

TEST_F(snsd_server_ut, case6_server_invalid_ver)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    test_obj.ver = 0x5;
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}

TEST_F(snsd_server_ut, case7_server_long_tlv_len)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    test_obj.tlv_inject = 100;
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_single_nt_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}
ssize_t recvmsg_small_msg(int sockfd, struct msghdr *msg, int flags)
{
    (void)recvmsg_single_nt_stub(sockfd, msg, flags);
    return 5;
}

ssize_t recvmsg_mjumbo_msg(int sockfd, struct msghdr *msg, int flags)
{
    (void)recvmsg_single_nt_stub(sockfd, msg, flags);
    return 2048;
}

TEST_F(snsd_server_ut, case8_server_small_msg)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_small_msg));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}

TEST_F(snsd_server_ut, case9_server_jumbo_msg)
{
    ASSERT_TRUE(test_obj.sock >= 0);

    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_mjumbo_msg));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);
    
    sleep(2);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 1);
}

TEST_F(snsd_server_ut, case10_server_update_multi_ip)
{
    struct snsd_port_related_info port_info;
    int ret;
    ASSERT_TRUE(test_obj.sock >= 0);

    memset(&port_info, 0, sizeof(port_info));
    for (int i = 0; i < SNSD_MAX_IP_PHYPORT; i++) {
        memcpy(port_info.ip, test_obj.local_ip[i], IPV4_ADDR_LENGTH);
        
        ret = snsd_update_sock_ip(test_obj.sock, &port_info, SNSD_UPDATE_ADD_IP);
        EXPECT_EQ(ret, 0);
    }
}

TEST_F(snsd_server_ut, case11_server_invalid_ip)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_invalid_ip_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);

    sleep(1);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 0);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 0);
}

TEST_F(snsd_server_ut, case12_server_last_ip)
{
    ASSERT_TRUE(test_obj.sock >= 0);
    memcpy(test_invalid_ip, &test_obj.local_ip[SNSD_MAX_IP_PHYPORT - 1], 
        IPV4_ADDR_LENGTH);

    MOCKER(recvmsg)
        .stubs()
        .will(invoke(recvmsg_invalid_ip_stub));
    snsd_ut_common_stub();
    snsd_client_notify(test_obj.sock);

    sleep(1);
    EXPECT_EQ(test_obj.cnt.connect_msg_cnt, 0);
    EXPECT_EQ(test_obj.cnt.disconnect_msg_cnt, 1);
    EXPECT_EQ(test_obj.cnt.ack_msg_cnt, 1);
    EXPECT_EQ(snsd_get_drop_msg_cnt(), 0);
}
