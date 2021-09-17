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
#include "snsd_server.h"
#include "snsd_conn_peon.h"
#include "snsd_log.h"
#include "snsd_mgt.h"
#include "snsd_reg.h"
#include "snsd_switch.h"
#include "snsd_direct.h"

struct usr_command {
    const char *cmd;
    void (*cmd_handle)(void);
};

#define print_info(f, x...)\
    do { \
        printf(f "\n", ##x); \
        (void)fflush(stdout); \
    } while (0)

void show_help(void)
{
    print_info("This is the nvme-snsd. Usage:");
    print_info("1: Before software installation, you must configure /etc/nvme/snsd.conf.");
    print_info("2: There are two software packages, nvme-snsd-xxx-linux.x86_64.rpm and nvme-snsd-xxx-linux.aarch64.rpm."
        "\n\tnvme-snsd-xxx-linux.x86_64.rpm is installed on x86 hosts,"
        "\n\tnvme-snsd-xxx-linux.aarch64.rpm is installed on ARM hosts.");
    print_info("3: Software installation"
        "\n\tNote: Run the following command in the directory where the "
        "installation package is stored on the host(the root permission is required)"
        "\n\trpm -ivh nvme-snsd-xxx.rpm.");
    print_info("4: Query the service"
        "\n\tsystemctl status nvme-snsd.");
    print_info("5: Stop the service"
        "\n\tsystemctl stop nvme-snsd"
        "\n\tsystemctl disable nvme-snsd");
    print_info("6: Restart the service"
        "\n\tsystemctl enable nvme-snsd"
        "\n\tsystemctl start nvme-snsd");
    print_info("7: Uninstall software"
        "\n\trpm -e nvme-snsd");
    return;
}

void show_version(void)
{
    print_info("SNSD VERSION: %s", SNSD_VERSION);
    return;
}

void special_process(const char *argv)
{
    struct usr_command commands[] = {
        {"--help",      show_help},
        {"-h",          show_help},
        {"--version",   show_version},
        {"-v",          show_version},
        {NULL},
    };
    int i;
    int size = sizeof(commands) / sizeof(struct usr_command);

    for (i = 0; i < size && commands[i].cmd_handle != NULL; i++) {
        if (strcmp(commands[i].cmd, argv) == 0) {
            commands[i].cmd_handle();
            return;
        }
    }

    print_info("snsd: unrecognized option '%s'.", argv);
    print_info("Use 'nvme-snsd --help' for a complete list of options.");
    print_info("Use 'nvme-snsd --version' for checking the software version.");

    return;
}

void port_handle(void)
{
    bool quit;
    unsigned int poll_count = SWITCH_POLL_INTEVAL;

    LIST_HEAD(direct_port_list_head);
    LIST_HEAD(switch_port_list_head);

    do {
        switch_port_handle(&switch_port_list_head, poll_count);
        direct_port_handle(&direct_port_list_head, poll_count);
        quit = snsd_help_run();
        usleep(POLL_INTERVAL_TIME);

        poll_count++;
    } while (quit != true);

    snsd_free_net_list(&direct_port_list_head);
    snsd_free_net_list(&switch_port_list_head);

    return;
}

int main(int argc, char *argv[])
{
    int ret;

    if (argc > 2) {
        printf("Error: Invalid argument(%d).\n", argc);
        return -EINVAL;
    }

    /* 2 parameters indicate user commands */
    if (argc == 2) {
        special_process(argv[1]);
        return -EINVAL;
    }

    snsd_log_init();
    SNSD_PRINT(SNSD_INFO, "SNSD VERSION: %s", SNSD_VERSION);

    ret = snsd_cfg_init();
    if (ret != 0)
        return ret;

    ret = peon_init();
    if (ret != 0) {
        snsd_cfg_exit();
        return ret;
    }

    switch_port_init();

    ret = snsd_server_run();
    if (ret != 0) {
        peon_exit();
        snsd_cfg_exit();
        snsd_log_exit();
        return ret;
    }

    port_handle();

    snsd_server_exit();
    peon_exit();
    snsd_cfg_exit();
    snsd_log_exit();

    return 0;
}
