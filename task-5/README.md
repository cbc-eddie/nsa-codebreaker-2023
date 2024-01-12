# Task 5 - Follow the Data, Part 1
![Static Badge](https://img.shields.io/badge/Categories-Reverse%20Engineering%2C%20Forensics-blue)
![Static Badge](https://img.shields.io/badge/Points-500-light_green)

> Based on the recovered hardware the device seems to to have an LTE modem and SIM card implying it connects to a GSM telecommunications network. It probably exfiltrates data using this network. Now that you can analyze the entire firmware image, determine where the device is sending data.
> 
> Analyze the firmware files and determine the IP address of the system where the device is sending data.
> 
> ---
> Prompt:
> - Enter the IP address (don't guess)

## Solution
Now that we've found the correct password for the encrypted partition, we can decrypt it with `cryptsetup` and mount it locally.

```
echo -n leantech85e | openssl sha1 | awk '{print $NF}' | cryptsetup open enc.part part
mkdir agent
mount /dev/mapper/part agent
```

Inspecting its contents reveals three executables (`agent`, `diagclient`, and `dropper`) along with a `config` file and a `start` script. There's also an empty file named `agent_restart`. Remembering the init script found during Task 4, we know the `start` script is ran after the parition is succesfully decrypted and mounted, so we'll start there. 

```bash
#!/bin/sh

DIR=/agent
PROC=agent
RESTART_FILE=agent_restart

# start the navigation service
/bin/nav

mkdir -p /tmp/upload
dmesg > /tmp/upload/boot_log_`date -Iseconds`

# start agent and restart if it exists
while [ 1 ]; do
    if [ ! -e $DIR/$RESTART_FILE ]; then
        break
    fi
    if [ -z "`ps -o comm | egrep ^${PROC}$`" ]; then
        $DIR/$PROC $DIR/config
    fi
    sleep 10
done
```

The `start` script's primary purpose is to launch the `agent` executable and then continually check that it's still running. If it doesn't detect that it's running, it relaunchs it and will continue to do this as long as the restart file `agent_restart` is still present. When launching the `agent` executable, it provides the `config` file as an argument so we'll take a look at that next.

```bash
logfile = "/tmp/log.txt"

# levels 0 (trace) - 5 (fatal)
loglevel = 1

daemonize = true

id_file = "/private/id.txt"
ssh_priv_key = "/private/id_ed25519"
priv_key = "/private/ecc_p256_private.bin"

cmd_host = "0.0.0.0"
cmd_port = 9000

collectors_usb = [ "/dev/ttyUSB0", "/dev/ttyUSB1" ]
collectors_ipc = [ "/tmp/c1.unix", "/tmp/c2.unix" ]
collect_enabled = true
dropper_exe = "/agent/dropper"
dropper_config = "/tmp/dropper.yaml"
dropper_dir = "/tmp/upload"

navigate_ipc = "/tmp/nav_service.unix"

key_file = "/agent/hmac_key"
restart_flag = "/agent/agent_restart"
```

Within the configuration options passed to the `agent`, we see several related to the `dropper` executable including one named `dropper_dir` that has a value of `/tmp/upload`. The goal of this task is to find where the device is exfiltrating data, so this sticks out as something that might be particularly relevant. We'll take a closer look at the `agent` executable to see if we can figure out how it's using these configuration options.

After opening `agent` within Binary Ninja, we can search for the `dropper` strings we're interested in and then look for any cross references to see where they're being used. We're led to a function located at `sub_400518` with an excerpt of the decompiled code below. We can see references to the `dropper` strings as well as some of the other strings found in the configuration file. Additionally, we can see references to the strings `waiting for other threads to finish`, `removing restart file`, and `usage: %s config\n`. Based on the information we've gathered so far, it looks like this function is responsible for parsing the configuration file and potentially launching some threads. It will also print the binary's usage string if the executable is ran without providing a configuration file or error strings if it can't resolve the path or properly parse the file.

![](./images/dropper_strings.png)

Prior to the reference to the `waiting for other threads to finish` string, we see three calls to a function located at `sub_4218e0` that appears to take other function locations as one of its arguments. Inspecting the `sub_4218e0` function closer, we'll also find reference to the string `pthread_create.c`, so we can conclude it's likely responsible for creating a new thread. Each of the three functions it launches in these threads begin by printing a string that gives us a good idea of what they do.

```
sub_402b34 => "starting upload thread"
sub_401794 => "starting collect thread"
sub_401220 => "starting cmd thread"
```

Renaming the thread creation function and some of its arguments from the above image can give us a clearer picture of what's happening.

![](./images/threads.png)

Since we're primarily concerned with where the data is being exfiltrated to for this task, we'll dig into the `sub_upload` function next. The full decompiled function is included below.

![](./images/sub_upload.png)

The function contains references to the database strings `DB_DATABASE`, `DB_COLLECTION`, and `DB_URL`. Right after those references, it calls a function located at `sub_4356a0`. Drilling down on this function, we see it eventually invokes the `execve` syscall and executes whatever program was passed to it as an argument. In this case, it's the `dropper` executable so we'll pivot over to that.

![](./images/execve.png)

After opening the `dropper` executable in Binary Ninja, we can inspect some of the strings where we'll find references to the [MongoDB Go driver](https://www.mongodb.com/docs/drivers/go/current/). This tracks with some of the database strings we found in `agent` since Mongo stores its records in collections. We'll look at the `main.main` function to see if we can get an idea of what this program does.

![](./images/dropper_main.png)

We can see a call to the function `dropper/pkg/exfil.Connect` which calls some of the MongoDB driver functions for connecting to a database. The inclusion of the word `exfil` in the package name tells us we're in the right place for solving this task. We want to know exactly where this dropper exfiltrates data to, and prior to establishing a connection we can see a call to `dropper/config.ReadConfig` which is passed a command line argument. Digging into `dropper/config.ReadConfig`, we find calls to two additional functions, `dropper/config.read_file` and `dropper/config.read_env`. A decompiled excerpt from `dropper/config.read_file`, which has the command line argument from the parent function passed through to it, is included below.

![](./images/dropper_read_file.png)

Based on the above, the function attempts to open a file using `os.OpenFile`. If that fails, it calls the function `dropper/config.read_file2` and returns. However if opening the file succeeds, it reads from the file and passes the content to the function `compress.bzip2.newBitReader` and eventually to a YAML decoder. This tells us it expects the config file to be compressed with `bzip2`. We can confirm this by calling the `dropper` executable with a non-empty file that is not compressed with `bzip2` and viewing the error output.

```
~ # echo test > test
~ # agent/dropper test
yaml: input error: bzip2 data invalid: bad magic value
```

As mentioned above, if it fails to open the config file provided as a command line argument due to it being non-existant, it instead calls the function `dropper/config.read_file2`. A decompiled excerpt of this function is included below.

![](./images/dropper_read_file2.png)

In the above image we can see the `dropper/config.read_file2` function using a call to `os.OpenFile` to access `/proc/self/exe`. Unlike in C, strings stored in Go binaries are not null-terminated so Binary Ninja has trouble delineating which part of the string is actually passed to the function. We know that `/proc/self/exe` is a way for a program to access its own executable, so we can infer that this is what it's actually opening. Once successfully opened, it seeks to `-4`, or four bytes from the end of the file, and then interprets those bytes as an integer. The last four bytes of the file are `\x00\x00\x00\xbd` or `189`. It then uses that value to seek back even further, ending up at `193` bytes from the end of the file. From there it reads `189` bytes and then writes those bytes back into the non-existant file it originally failed to open before recalling the `dropper/config.read_file` function with the newly created file. Finally, it removes the file and any traces of the embedded config.

We know from previously analyzing the `dropper/config.read_file` function that it decompresses the config contents using `bzip2` and then parses it as a YAML file.  With this information, we can manually extract those bytes and decompress them to see what type of information the config file holds with the following one-liner.

```
~ # tail -c 193 agent/dropper | head -c 189 | bunzip2
database:
  collection: files
  database: snapshot-28c5e8e20fcc
  url: mongodb://maintenance:ed4faa4d05f294@100.102.144.34:27017/?authSource=snapshot-28c5e8e20fcc
server:
  directory: /tmp/upload
```

The above output shows the information is exfiltrated to a MongoDB server located at `100.102.144.34`. This is the information we were interested in and the solution to the task. The `solve.py` script in this repository performs the same extraction and decompression using Python.


## Alternate Solutions

### Binwalk
Since the config file is compressed with `bzip2` and tacked onto the end of the executable, a program such as `binwalk` that looks for embedded files is able to find and extract it fairly easily.

```bash
binwalk -e dropper
```

The above command will create a directory named `_dropper.extracted` before automatically extracting and decompressing the configuration as `AF38A2`.

```
~ # cat _dropper.extracted/AF38A2
database:
  collection: files
  database: snapshot-28c5e8e20fcc
  url: mongodb://maintenance:ed4faa4d05f294@100.102.144.34:27017/?authSource=snapshot-28c5e8e20fcc
server:
  directory: /tmp/upload
```

This would give us everything we need to solve the task and successfully connect to the Mongo database for Task 6.

### Packet Sniffing
When the `dropper` executable is provided with a non-existant config file as an argument, it will extract and parse the embedded config file and attempt to connect to the MongoDB server. It quickly deletes this extracted file before we can read it, but it's possible to install `tcpdump` in the Docker container and capture the outgoing connection to see where it goes.

```
root@0cff0618a6f2:~# tcpdump 'dst port 27017'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tap0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
08:37:40.450407 IP 10.101.255.254.40648 > 100.102.144.34.27017: Flags [S], seq 2500192648, win 64240, options [mss 1460,sackOK,TS val 4235396404 ecr 0,nop,wscale 7], length 0
```

The above method would give us the correct exfiltration IP address of `100.102.144.34` and allow us to complete the current task, but we would be missing the additional information that we need to successfully connect to the MongoDB server for Task 6.
