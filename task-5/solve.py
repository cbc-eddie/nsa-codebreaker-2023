#!/usr/bin/env python3

import bz2
import struct

seek = -4

with open("./agent/dropper", "rb") as infile:
    dropper = infile.read()

# Get the size of the config file
size = abs(struct.unpack(">L", dropper[seek:])[0])

# Extract the compressed config file
compressed = dropper[seek-size:seek]

# Decompress the config file
config = bz2.decompress(compressed).decode()
print(config)
