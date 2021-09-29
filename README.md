# redme
# README

## Nvme-snsd  
This is an independently deployable software that can simplify service deployment and configuration while reducing the impact of link failures on services .When the storage device goes online, NVMe over Fabric target association/connection will be automatically created. Once a path between the host and the storage is not reachable/offline, the device can detect the path change in time and switch the current fault path service to another to reduce the service downtime.

### To compile:  
Run:  
```
$./build/build_arm.sh  
or  
$./build/build_x86_64.sh  
```
### To install:  
Step1:Create a configuration file.  
    1.Create the configuration file directory mkdir nvme in the /etc directory on the host.  
    2.Create the configuration file snsd.conf in the /etc/nvme/ directory. The file content is as follows:  

    /*-----------------------------------------------*  
     *             Configuration Body                *  
     *-----------------------------------------------*/  
    [BASE]  
    ; The delay time of disconnecting device when net link down. Unit is second.  
    ; The recommended value is 0.  
    restrain-time = 0  
      
    [SW]  
    ; Switching network configuration, mandatory :--host-traddr, --protocol  
    ; If "--host-traddr" is set to "any", other IP addresses cannot be configured for the switching network. All customer networks support SNSD  
    ; eg:  
    ; --host-traddr = xxxx | --protocol = (roce/tcp/iscsi)  
    --host-traddr = 2.20.10.2 | --protocol = roce  
    --host-traddr = 2.50.10.2 | --protocol = roce  
      
    [DC]  
    ; Configuration of the directly connected network, mandatory :--host-traddr,--protocol,--traddr  
    ; eg:  
    ;  --host-traddr = xxxx | --traddr = xxxx | --protocol = (roce/tcp/iscsi)  
    --host-traddr = 123.2.1.122 | --traddr = 1.1.1.2 | --protocol = roce  
    --host-traddr = 2.30.10.2 | --traddr = 1.1.1.2 | --protocol = roce
    Each line indicates a complete connection configuration. Each configuration item is separated by a vertical bar (|). 
    The configuration consists of three parts: BASE, SW, and DC. 
        BASE: The restrain time of disconnecting device when net link down. Unit is second.

        SW: Switching network. Configure the IP address of the host that supports plug-and-play and fast detection. 
            --host-traddr = any: All customer networks support SNSD by default. 

        DC: Direct network: Configure host information and storage array information that support plug-and-play and quick detection. 
            Note: The value is not affected by any. 

###### Configuration Item:
    The following parameters are supported in the BASE field (some optional parameters depend on the NVMe driver version):
        --restrain-time     Indicates the delay for disconnecting a device when the network link is disconnected. The unit is second. This parameter is optional.
        --trsvcid           Specifies the port number of the TGT. This parameter is optional.
        --hostnqn           Indicates the hostnqn. This parameter is optional.
        --hostid            Specifies the host ID. This parameter is optional.
        --nr-io-queues      Specifies the number of I/O queues. This parameter is optional.
        --nr-write-queues   Specifies the number of write queues. This parameter is optional.
        --nr-poll-queues    Indicates the number of poll queues. This parameter is optional.
        --queue-size        Specifies the I/O queue depth. This parameter is optional.
        --keep-alive-tmo    Specifies the heartbeat timeout interval. This parameter is optional.
        --reconnect-delay   Indicates the retry interval after link disconnection. This parameter is optional.
        --ctrl-loss-tmo     Specifies the controller disconnection time. This parameter is optional.
        --duplicate_connect Specifies whether multiple connections can be set up on a port. This parameter is optional.
        --disable_sqflow    Cancels SQ flow control on a host. This parameter is optional.
        --hdr_digest        Enables the transmission protocol header. This parameter is optional.
        --data_digest       Enables the transmission protocol data. This parameter is optional.
        --standard          Set special standard, eg: CMCC, ODCC, default value is ODCC. This parameter is optional.

    The following parameters are supported in the SW/DC field (some optional parameters depend on the NVMe driver version):
        --traddr            Specifies the IP address of the TGT. This parameter is mandatory for the DC field and not supported by the SW field.
        --trsvcid           Specifies the port number of the TGT. This parameter is optional.
        --host-traddr       Specifies the IP address used by the host. This parameter is mandatory.
        --hostnqn           Indicates the hostnqn. This parameter is optional.
        --hostid            Specifies the host ID. This parameter is optional.
        --nr-io-queues      Specifies the number of I/O queues. This parameter is optional.
        --nr-write-queues   Specifies the number of write queues. This parameter is optional.
        --nr-poll-queues    Indicates the number of poll queues. This parameter is optional.
        --queue-size        Specifies the I/O queue depth. This parameter is optional.
        --keep-alive-tmo    Specifies the heartbeat timeout interval. This parameter is optional.
        --reconnect-delay   Indicates the retry interval after link disconnection. This parameter is optional.
        --ctrl-loss-tmo     Specifies the controller disconnection time. This parameter is optional.
        --duplicate_connect Specifies whether multiple connections can be set up on a port. This parameter is optional.
        --disable_sqflow    Cancels SQ flow control on a host. This parameter is optional.
        --hdr_digest        Enables the transmission protocol header. This parameter is optional.
        --data_digest       Enables the transmission protocol data. This parameter is optional.
        --protocol          Indicates the transmission protocol type. The value can be RoCE, TCP, or iSCSI. Currently, only RoCE is supported. This parameter is mandatory.

- [BASE] field: Configures the base config which used by DC and SW, If the DC or SW has the same configuration type, the DC or SW configuration takes precedence.
- [SW] field: Configure IP addresses, protocols, and link parameters for hosts on the switching network to support NVMe over fabric.
- [DC] field: Configures IP addresses, corresponding array IP addresses, protocols , and link parametersfor the hosts on the direct connection network to support the NVMe over fabric.  

Step2: Run  `$ rpm -ivh nvme-snsd-x.xx.xxx-linux.xxxxx.rpm`  

Step3: Run  `$ systemctl status nvme-snsd` command to query the installation result. If active (running) is displayed,nvme-snsd has been installed.  

## To uninstall:  
Run:  
`$ rpm –e nvme-snsd`  

## Impact and restrictions  
This section describes constraints and restrictions of nvme-snsd.  
1.Only Linux operating systems are supported. Windows and VMware operating systems are not.  
2.One physical port of a host or storage system can not support multiple IP addresses.  Only one is allowed.  
3.IPv6 addresses are not supported.  
## Supported switchs  
Models:CloudEngine 6866 , CloudEngine 8851 and CloudEngine 16800
## License
BSD 3-Clause License( https://choosealicense.com/licenses/bsd-3-clause/ )