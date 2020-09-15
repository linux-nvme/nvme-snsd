# README

## Nvme-snsd  
This is an independently deployable software that can simplify service deployment and configuration while reducing the impact of link failures on services .When the storage device goes online, NVMe over Fabric target association/connection will be automatically created. Once a path between the host and the storage is not reachable/offline, the device can detect the path change in time and switch the current fault path service to another to reduce the service downtime.

### To compile:  
Run:  
```
$./build/build_arm.sh  
or  
$./build/ build_x86_64.sh  
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
- [BASE] field: Configures the timeout interval delivered to the driver when the link is disconnected. By default, you do not need to configure the timeout interval.  
- [SW] field: Configures IP addresses and protocols for the hosts on the switching network to support the NVMe over fabric.  
- [DC] field: Configures IP addresses, corresponding array IP addresses, and protocols for the hosts on the direct connection network to support the NVMe over fabric.  

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
