# coding: utf-8
# Copyright(C) 2019 FireEye, Inc. All Rights Reserved.
#
# FLASHMINGO!
# Basic hexdump implementation


def hexdump(data, block_size=16):
    """This is a no-frills hex dump

    There is a hexdump module in pip 
    but I wanted to reduce dependencies 
    """

    data_len = len(data)
    i = 0

    while True:
        a = i * block_size
        b = (i + 1) * block_size
        chunk = data[a : b]

        # data is of type string in Python 2.7 -> ord
        hex_chunk = ' '.join("{:02x}".format(ord(c)) for c in chunk)

        if len(chunk) < block_size:
            delta = block_size - len(chunk)

            # Padding
            padding = " " * (2 * delta)
            hex_chunk += padding

        print("{hex}\t{asc}".format(
            hex=hex_chunk,
            asc=chunk))

        if b > data_len:
            break

        i += 1

