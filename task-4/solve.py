#!/usr/bin/env python3

import hashlib
import itertools
import string
import subprocess
import sys

# Requires the hostname from the firmware and the path to the encrypted partition
if len(sys.argv) <= 2:
    print("usage: solve.py [hostname] [partition]")
    exit()

hostname = sys.argv[1]
partition = sys.argv[2]

# Build each password using the possible combinations of three hex characters
# Save each password in a dictionary with the hash as the key for easy lookup
print("[+] Building dictionary")
passwords = {}
with open("dictionary.txt", "w") as outfile:
    for a, b, c in set(itertools.product(string.hexdigits.lower(), repeat=3)):
        password = hostname + a + b + c
        digest = hashlib.sha1(password.encode()).hexdigest()

        passwords[digest] = password
        outfile.write(digest + "\n")

# Extract the LUKS header from the encrypted partition
print("[+] Extracting LUKS header")
subprocess.run(["dd", f"if={partition}", "of=header.luks", "bs=512", "count=4097"], capture_output=True)

# Bruteforce the decryption key using hashcat
print("[+] Running hashcat (might take a little while)")
output = subprocess.run(["hashcat", "-m", "14600", "-O", "header.luks", "dictionary.txt"], capture_output=True)

# Find the password that hashes to the correct key
key = output.stdout.decode().split("header.luks:")[1].split("\n")[0]
password = passwords[key]
print(f"[+] Password: {password}")
