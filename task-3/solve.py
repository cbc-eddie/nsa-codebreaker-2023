#!/usr/bin/env python3

import socket
import time

host = "127.0.0.1"
shell_prompt = b"=> "
wait = 0.25

# Set up the first listener on port 10000
sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock1.bind((host, 10000))
sock1.listen()

# Set up the second listener on port 10001
sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2.bind((host, 10001))
sock2.listen()

# Accept the connection and read from the socket until it's ready to accept a command
conn, addr = sock1.accept()
data = b""
while shell_prompt not in data:
    time.sleep(wait)
    data += conn.recv(1024)
print(f"[+] Accepted the connection")

# Print the environment variables to find the key address
conn.send(b"printenv \n")
data = b""
while shell_prompt not in data:
    time.sleep(wait)
    data += conn.recv(1024)

keyaddr = data.split(b"keyaddr=")[1].split(b"\r")[0].decode()
print(f"[+] Key address: 0x{keyaddr}")

# Use the key address along with the "md" command to print the key
conn.send(f"md.b {keyaddr} 10\n".encode())
data = b""
while shell_prompt not in data:
    time.sleep(wait)
    data += conn.recv(1024)

key = data.replace(b" ", b"").split(b":")[1][:32].decode()
print(f"[+] Key: {key}")
