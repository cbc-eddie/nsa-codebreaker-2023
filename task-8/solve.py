#!/usr/bin/env python3

import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

# Only the data portion from the packet, beginning with the attacker's public key
packet = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5aa296041eb58230545dd0cd82084c1ba7ee8adeb029c8d18dbb7cc4552295b4d3d3ff67aaa9fa785f0bb937d08f00e00348e56c979e0bdef487418092c3b9a30fe71604e81463f50be7e162faaace670fb6361288ebb8414db54b609fd66e29954f48d127aef9d4219b320e95363f4d7b5f69a214fbdb091be3b214ca929be5d0f72afeb032084205b794dd9ab449ff23a64a08685adc2a8a2563a2eff8c255f8f3a8f7a1507a7516fd6b75ad73a16ad67f55cf74a324485055a93581a9154547e096c6cc6574a980088dfb93a557f714af0e1801a72f2ed8e3db610e03117d3")
target_hmac = packet[64:96]
ciphertext = packet[96:]

with open("private/ecc_p256_pub.bin", "rb") as infile:
    pub = infile.read()

# Key is derived from the first 16 bytes of the SHA256 of the shared secret.
# Since the attacker's public key is just the generator point, their private
# key is 1 so the shared secret is the X value of our public key
pub_x = pub[:32]
pub_x_hash = hashlib.sha256(pub_x).digest()
key = pub_x_hash[:16]

# AES uses counter mode with the intial value calculated using 8 bytes from
# shared secret hash combined with \x00\x00\x00\x00\x00\x00\x00\x01
ctr_value = bytes_to_long(pub_x_hash[16:24] + b"\x00"*7 + b"\x01")
ctr = Counter.new(128, initial_value=ctr_value)

cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
plaintext = cipher.decrypt(ciphertext)
new_hmac_key = plaintext.split(b"\x00")[126]
print(f"[+] Extracted new HMAC key from packet: {new_hmac_key.decode()}")

# Brute force the previous HMAC key based on the format of the new key
for i in range(100000):
    prev_hmac = "secret_key_" + str(i).zfill(5)

    check = hmac.new(prev_hmac.encode(), plaintext, hashlib.sha256).digest()
    if check == target_hmac:
        print(f"[+] Found previous HMAC key: {prev_hmac}")
        break
