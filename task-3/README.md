# Task 3 - Analyze the Firmware
![Static Badge](https://img.shields.io/badge/Categories-Emulation-blue)
![Static Badge](https://img.shields.io/badge/Points-200-light_green)

> Leveraging that datasheet enabled you to provide the correct pins and values to properly communicate with the device over UART. Because of this we were able to communicate with the device console and initiate a filesystem dump.
> 
> To begin analysis, we loaded the firmware in an analysis tool. The kernel looks to be encrypted, but we found a second-stage bootloader that loads it. The decryption must be happening in this bootloader. There also appears to be a second UART, but we don't see any data coming from it.
> 
> Can you find the secret key it uses to decrypt the kernel?
> 
> Tips:
> - You can emulate the loader using the provided QEMU docker container. One download provides the source to build your own. The other is a pre-built docker image. See the README.md from the source download for steps on running it.
> - Device tree files can be compiled and decompiled with dtc.
> 
> Downloads:
> - U-Boot program loader binary ([u-boot.bin](./downloads/u-boot.bin))
> - Recovered Device tree blob file ([device_tree.dtb](./downloads/device_tree.dtb))
> - Docker source files to build the QEMU/aarch64 image ([cbc_qemu_aarch64-source.tar.bz2](./downloads/cbc_qemu_aarch64-source.tar.bz2))
> - Docker image for QEMU running aarch64 binaries (cbc_qemu_aarch64-image.tar.bz2)
> ---
> Prompt:
> - Enter the decryption key u-boot will use.

## Solution
The device has been successfully identified, the firmware was dumped, and we're now tasked with analyzing the second-stage bootloader. We can use either the Docker source files or the Docker image to get our environment set up for this task. We'll use the source files by first unpacking them with `tar xvf cbc_qemuaarch64-source.tar.bz2` and then following along with the instructions in the `README.md` file to get everything up and running.

Once the container is running and we've successfully passed through the directory containing the `u-boot.bin` and `device_tree.dtb` files, we can spawn a couple shells within the container, set up our netcat listeners, and then run the provided QEMU command. If everything is configured correctly, we'll see the below U-Boot output coming through on port 10000.

```
U-Boot 2022.04

DRAM:  128 MiB
Core:  42 devices, 11 uclasses, devicetree: board
Flash: 32 MiB
Loading Environment from Flash... *** Warning - bad CRC, using default environment

"reg" resource not found
probed pl011@9000000
In:    pl011@9000000
Out:   pl011@9000000
Err:   pl011@9000000
Net:   No ethernet found.
Hit any key to stop autoboot:  0
starting USB...
No working controllers found
USB is stopped. Please issue 'usb start' first.
"reg" resource not found
scanning bus for devices...

Device 0: unknown device
"reg" resource not found

Device 0: unknown device
starting USB...
No working controllers found
"reg" resource not found
No ethernet found.
No ethernet found.
=>
```

Once it's done printing, we'll be dropped into a U-Boot shell where we can run commands. Using `help` will give provide a listing of the other commands available to us. A truncated portion of the output is included below with some additional details on common commands available [here](https://docs.u-boot.org/en/latest/usage/index.html). 

```
=> help
help
?         - alias for 'help'
aes       - AES 128/192/256 CBC encryption
base      - print or set address offset
bdinfo    - print Board Info structure
...
usb       - USB sub-system
usbboot   - boot from USB device
version   - print monitor, compiler and linker version
virtio    - virtio block devices sub-system
```

We can see the `aes` command included in the above list. Running it shows the expected arguments which are included below and also available in the [source code](https://github.com/u-boot/u-boot/blob/master/cmd/aes.c).

```
=> aes
aes
aes - AES 128/192/256 CBC encryption

Usage:
aes [.128,.192,.256] enc key iv src dst len - Encrypt block of data $len bytes long
                             at address $src using a key at address
                             $key with initialization vector at address
                             $iv. Store the result at address $dst.
                             The $len size must be multiple of 16 bytes.
                             The $key and $iv must be 16 bytes long.
aes [.128,.192,.256] dec key iv src dst len - Decrypt block of data $len bytes long
                             at address $src using a key at address
                             $key with initialization vector at address
                             $iv. Store the result at address $dst.
                             The $len size must be multiple of 16 bytes.
                             The $key and $iv must be 16 bytes long.
```

The command expects a `key` and `iv` which are likely present somewhere in the firmware. This type of information is sometimes stored in [environment variables](https://docs.u-boot.org/en/latest/usage/environment.html) which we can view using the `printenv` [command](https://docs.u-boot.org/en/latest/usage/cmd/printenv.html).

```
=> printenv
printenv
arch=arm
baudrate=115200
board=qemu-arm
board_name=qemu-arm
boot_a_script=load ${devtype} ${devnum}:${distro_bootpart} ${scriptaddr} ${prefix}${script}; source ${scriptaddr}
boot_efi_binary=load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_r} efi/boot/bootaa64.efi; if fdt addr ${fdt_addr_r}; then bootefi ${kernel_addr_r} ${fdt_addr_r};else bootefi ${kernel_addr_r} ${fdtcontroladdr};fi
boot_efi_bootmgr=if fdt addr ${fdt_addr_r}; then bootefi bootmgr ${fdt_addr_r};else bootefi bootmgr;fi
boot_extlinux=sysboot ${devtype} ${devnum}:${distro_bootpart} any ${scriptaddr} ${prefix}${boot_syslinux_conf}
boot_net_usb_start=usb start
boot_pci_enum=pci enum
boot_prefixes=/ /boot/
boot_script_dhcp=boot.scr.uimg
boot_scripts=boot.scr.uimg boot.scr
boot_syslinux_conf=extlinux/extlinux.conf
boot_targets=usb0 scsi0 virtio0 dhcp
bootcmd=run distro_bootcmd
bootcmd_dhcp=devtype=dhcp; run boot_net_usb_start; run boot_pci_enum; if dhcp ${scriptaddr} ${boot_script_dhcp}; then source ${scriptaddr}; fi;setenv efi_fdtfile ${fdtfile}; setenv efi_old_vci ${bootp_vci};setenv efi_old_arch ${bootp_arch};setenv bootp_vci PXEClient:Arch:00011:UNDI:003000;setenv bootp_arch 0xb;if dhcp ${kernel_addr_r}; then tftpboot ${fdt_addr_r} dtb/${efi_fdtfile};if fdt addr ${fdt_addr_r}; then bootefi ${kernel_addr_r} ${fdt_addr_r}; else bootefi ${kernel_addr_r} ${fdtcontroladdr};fi;fi;setenv bootp_vci ${efi_old_vci};setenv bootp_arch ${efi_old_arch};setenv efi_fdtfile;setenv efi_old_arch;setenv efi_old_vci;
bootcmd_scsi0=devnum=0; run scsi_boot
bootcmd_usb0=devnum=0; run usb_boot
bootcmd_virtio0=devnum=0; run virtio_boot
bootdelay=2
cpu=armv8
distro_bootcmd=scsi_need_init=; setenv nvme_need_init; virtio_need_init=; for target in ${boot_targets}; do run bootcmd_${target}; done
efi_dtb_prefixes=/ /dtb/ /dtb/current/
fdt_addr=0x40000000
fdt_high=0xffffffff
fdtcontroladdr=46ef0290
initrd_high=0xffffffff
ivaddr=467a0010
kernel_addr_r=0x40400000
keyaddr=467a0000
load_efi_dtb=load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} ${prefix}${efi_fdtfile}
loadaddr=0x40200000
nvme_boot=run boot_pci_enum; run nvme_init; if nvme dev ${devnum}; then devtype=nvme; run scan_dev_for_boot_part; fi
nvme_init=if ${nvme_need_init}; then setenv nvme_need_init false; nvme scan; fi
pxefile_addr_r=0x40300000
ramdisk_addr_r=0x44000000
scan_dev_for_boot=echo Scanning ${devtype} ${devnum}:${distro_bootpart}...; for prefix in ${boot_prefixes}; do run scan_dev_for_extlinux; run scan_dev_for_scripts; done;run scan_dev_for_efi;
scan_dev_for_boot_part=part list ${devtype} ${devnum} -bootable devplist; env exists devplist || setenv devplist 1; for distro_bootpart in ${devplist}; do if fstype ${devtype} ${devnum}:${distro_bootpart} bootfstype; then run scan_dev_for_boot; fi; done; setenv devplist
scan_dev_for_efi=setenv efi_fdtfile ${fdtfile}; for prefix in ${efi_dtb_prefixes}; do if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${efi_fdtfile}; then run load_efi_dtb; fi;done;run boot_efi_bootmgr;if test -e ${devtype} ${devnum}:${distro_bootpart} efi/boot/bootaa64.efi; then echo Found EFI removable media binary efi/boot/bootaa64.efi; run boot_efi_binary; echo EFI LOAD FAILED: continuing...; fi; setenv efi_fdtfile
scan_dev_for_extlinux=if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${boot_syslinux_conf}; then echo Found ${prefix}${boot_syslinux_conf}; run boot_extlinux; echo SCRIPT FAILED: continuing...; fi
scan_dev_for_scripts=for script in ${boot_scripts}; do if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${script}; then echo Found U-Boot script ${prefix}${script}; run boot_a_script; echo SCRIPT FAILED: continuing...; fi; done
scriptaddr=0x40200000
scsi_boot=run boot_pci_enum; run scsi_init; if scsi dev ${devnum}; then devtype=scsi; run scan_dev_for_boot_part; fi
scsi_init=if ${scsi_need_init}; then scsi_need_init=false; scsi scan; fi
stderr=pl011@9000000
stdin=pl011@9000000
stdout=pl011@9000000
usb_boot=usb start; if usb dev ${devnum}; then devtype=usb; run scan_dev_for_boot_part; fi
vendor=emulation
virtio_boot=run boot_pci_enum; run virtio_init; if virtio dev ${devnum}; then devtype=virtio; run scan_dev_for_boot_part; fi
virtio_init=if ${virtio_need_init}; then virtio_need_init=false; virtio scan; fi

Environment size: 4254/262140 bytes
```

Looking through the above output, we can find an environment variable named `keyaddr`. It's possible to use the `md` [command](https://docs.u-boot.org/en/latest/usage/cmd/md.html) to display memory at a specific address which would allow us to dump the key.

```
=> md
md
md - memory display

Usage:
md [.b, .w, .l, .q] address [# of objects]
```

The `md` command uses a data size argument to specify how the memory will be displayed. It can print the memory by byte, word (16 bits), long (32 bits), or quadword (64 bits). We'll use bytes to make sure the key is printed in the correct order.

```
=> md.b 467a0000 10
md.b 467a0000 10
467a0000: 40 0b e2 24 ac c6 26 e1 f8 16 b4 df 14 09 93 24  @..$..&........$
```

Cleaning up the above output gives us the 16-byte encryption key `400be224acc626e1f816b4df14099324`. The `solve.py` script can print the environment variables, grab the key address, and then use the `md` command to dump the key from memory. It sets up the appropriate listeners so it needs to either be run from within the container or ports `10000` and `10001` need to be passed through to the host.
