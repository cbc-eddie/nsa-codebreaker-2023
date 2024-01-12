# Task 4 - Emulate the Firmware
![Static Badge](https://img.shields.io/badge/Categories-Dynamic%20Reverse%20Engineering%2C%20Cryptography-blue)
![Static Badge](https://img.shields.io/badge/Points-500-light_green)

> We were able to extract the device firmware, however there isn't much visible on it. All the important software might be protected by another method.
> 
> There is another disk on a USB device with an interesting file that looks to be an encrypted filesystem. Can you figure out how the system decrypts and mounts it? Recover the password used to decrypt it. You can emulate the device using the QEMU docker container from task 3.
> 
> Downloads:
> - main SD card image ([sd.img.bz2](./downloads/sd.img.bz2))
> - USB drive image ([usb.img.bz2](./downloads/usb.img.bz2))
> - Linux kernel ([kernel8.img.bz2](./downloads/kernel8.img.bz2))
> - Device tree blob file for emulation ([bcm2710-rpi-3-b-plus.dtb.bz2](./downloads/bcm2710-rpi-3-b-plus.dtb.bz2))
> ---
> Prompt:
> - Enter the password used to decrypt the filesystem.

## Solution
With the firmware extracted, we now need to investigate an encrypted filesystem present on the device. We can use the [instructions](../task-3/downloads/cbc_qemu_aarch64-source.tar.bz2) included in the `README.md` from Task 3 to get our environment set up. Once it's configured, we can launch QEMU with the provided command. The below lines can be found interspersed in the boot log output from QEMU.

```
cryptsetup: opening /opt/part.enc
No key available with this passphrase.
mount: mounting /dev/mapper/part on /agent failed: No such file or directory
```

The above seems to indicate there's an encrypted partition that fails to decrypt and mount as part of the boot process. We can see the partition is located in the `/opt` directory, so we'll take a look and see if there's anything else stored there.

```
~ # ls -al /opt
total 28740
drwxr-xr-x    4 root     0             4096 May 15  2022 .
drwxr-xr-x   21 root     0             4096 Jan  1 00:17 ..
drwx------    2 root     0             4096 May 15  2022 .ssh
-rw-r--r--    1 root     0                9 May 15  2022 hostname
drwx------    2 root     0            16384 May 15  2022 lost+found
-rwxrwx---    1 root     0              443 May 15  2022 mount_part
-rw-r--r--    1 root     0         29360128 May 15  2022 part.enc
```

The directory also includes another file named `mount_part` that contains the below.

```bash
#!/bin/sh

SEC_DRIVE=$1
SEC_MOUNT=$2
ENC_PARTITION=$3
ENC_MOUNT=$4

[ ! -e $ENC_PARTITION ] && { echo "encrypted partition not found"; exit 1; }

mkdir -p $SEC_MOUNT
mount $SEC_DRIVE $SEC_MOUNT
NAME=`hostname`
ID=`cat /private/id.txt`

DATA="${NAME}${ID:0:3}"
echo "cryptsetup: opening $ENC_PARTITION"
echo -n $DATA | openssl sha1 | awk '{print $NF}' | cryptsetup open $ENC_PARTITION part
mkdir -p $ENC_MOUNT
mount /dev/mapper/part $ENC_MOUNT
```

This script accepts four arguments and uses them to mount two partitions. The second partition is decrypted before being mounted and is likely the filesystem that's referenced in the task description. We can use `grep` to search the rest of the system to see where the `mount_part` script is being called. This will give us additional context and let us see the exact arguments being passed to it.

```
~ # grep -lr mount_part /etc
/etc/init.d/rcS
```

Searching the system with `grep` points us to the file `/etc/init.d/rcS` which contains mention of `mount_part`. The full contents of the init script are included below and show the encrypted partition will be mounted at `/agent` if it's successfully decrypted. Once it's mounted, the script then runs `/agent/start`.

```bash
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
mount -a

for drv in /drivers/*.ko; do
  insmod $drv
done

[ -s /etc/hostname ] && hostname `cat /etc/hostname`

PRIV_IP=10.101.255.254

ifconfig lo 127.0.0.1 netmask 255.0.0.0
ifconfig lo up
ifconfig usb0 $PRIV_IP netmask 255.255.0.0
ifconfig usb0 up

ifconfig usb1 up
udhcpc -i usb1 -s /etc/udhcpc.script -b &

/sbin/dropbear -p $PRIV_IP:22

/opt/mount_part /dev/sda2 /private /opt/part.enc /agent
(/agent/start >/dev/null 2>&1) &
```

Going back to the `mount_part` script, we can see the last section of the file is responsible for constructing a variable named `DATA`, using `openssl` to calculate its SHA1 hash, and then using that hash as the password for the `cryptsetup open` command. The `DATA` variable is built by taking the hostname along with the first three bytes of the `/private/id.txt` file. In this case, the hostname of the device is `leantech`.

```
~ # hostname
leantech
```

Attempting to read the file `/private/id.txt` doesn't print anything which is what's leading to decryption failure. The file appears to have been corrupted. Given that we only use the first three bytes, we could try to brute force them with the information we have, but taking a closer look at the file with `ls` and `xxd` shows that it actually contains 36 null bytes.

```
~ # ls -al /private
total 40
drwxr-xr-x    3 root     0             4096 May 15  2022 .
drwxr-xr-x   21 root     0             4096 Jan  1 00:17 ..
-rw-------    1 root     0               96 May 15  2022 ecc_p256_private.bin
-rw-------    1 root     0               64 May 15  2022 ecc_p256_pub.bin
-rw-------    1 root     0               36 May 15  2022 id.txt
-rw-------    1 root     0              387 May 15  2022 id_ed25519
drw-------    2 root     0            16384 May 15  2022 lost+found
~ # xxd /private/id.txt
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000
```

This size of 36 bytes combined with the name `id.txt` hints that it likely contained a [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier) prior to being corrupted. UUIDs are 128-bit labels that typically contain 32 hex characters along with four hyphens in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Knowing that the first three characters of the file were hex characters significantly reduces are search space down to `16^3 = 4096`. We can use this information along with the hostname to build a list of the possible passwords. The following Python script will build a dictionary that we can use to bruteforce the decryption key.

```python
#!/usr/bin/env python3

import hashlib
import itertools
import string

hostname = "leantech"

with open("dictionary.txt", "w") as outfile:
    for a, b, c in set(itertools.product(string.hexdigits.lower(), repeat=3)):
        password = hostname + a + b + c
        digest = hashlib.sha1(password.encode()).hexdigest()

        outfile.write(digest} + "\n")
```

Now that we have a list of possible passwords, we can use `hashcat` or a dedicated tool such as [bruteforce-luks](https://github.com/glv2/bruteforce-luks) to find the correct one. We'll use `hashcat` along with the `-m 14600` mode option for LUKS encryption cracking. A list of the different modes along with example hashes can be found [here](https://hashcat.net/wiki/doku.php?id=example_hashes). For more efficient cracking, we can mount the first partition of the USB image provided with this task on our host machine and directly access the `part.enc` file using the below commands.

```bash
mkdir mnt
sudo losetup -P /dev/loop0 usb.img
sudo mount /dev/loop0p1 mnt
```

The encrypted parition we're interested in should now be located at `./mnt/part.enc`. Due to how `hashcat` [cracking works for LUKS partitions](https://hashcat.net/forum/thread-6225.html), we'll only need to use a porition of the encrypted file. We can extract this subsection using the following command.

```bash
dd if=./mnt/part.enc of=header.luks bs=512 count=4097
```

Now that we have a dictionary list and the LUKS header, we can finally crack it.
```bash
hashcat -m 14600 -O header.luks dictionary.txt
```

After running for a little while, `hashcat` eventually prints out the correct decryption key, `61c40a34a50be05e1f1dd63a96bf0f1f08f448fd`. The answer for the task is the actual password that hashes to this value, so we'll need to iterate through our inputs again to find which one's hash matches the key. The below script loops back through the passwords and prints out the correct one, which in this case is `leantech85e`.

```python
#!/usr/bin/env python3

import hashlib
import itertools
import string

hostname = "leantech"
target = "61c40a34a50be05e1f1dd63a96bf0f1f08f448fd"

for a, b, c in set(itertools.product(string.hexdigits.lower(), repeat=3)):
    password = hostname + a + b + c
    digest = hashlib.sha1(password.encode()).hexdigest()

    if digest == target:
        print(password)
        break
```

The `solve.py` script included in this repository accepts the firmware's hostname and the path to the encrypted partition as arguments and then attempts to find the correct password. It requires `hashcat` to be installed and for the encrypted partition to have been extracted from the USB image in order to work.
