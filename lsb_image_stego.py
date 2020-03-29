#!/usr/bin/env python3

import argparse
from PIL import Image
import random
import struct
import sys
import zlib
import os
import getpass
import shutil
import hashlib
from collections import deque
from termcolor import colored, cprint


MAX_FILE_SIZE = 2**30  # in bytes, i.e. 1GB
READ_CHUNK_SIZE = 1024  # in bytes
PRINT_PROGRESS_FREQ = 1024  # print progress every 1024 bytes


def print_progress(cur_nr, total, _type):
    """ Print progress of hiding / revealing """

    bar_count = shutil.get_terminal_size((80, 20)).columns // 2  # half the terminal width
    completed_bars = int(cur_nr * bar_count / total)
    remaining_bars = bar_count - completed_bars

    if cur_nr > 0:
        print("\033[1A\r\033[K", end="")  # clear previous line

    print_str = "    Progress: [" + colored(completed_bars * "=", color="green") + remaining_bars * "·" + "] "
    print_str += "(%d/%d %s)" % (cur_nr, total, _type)
    print(print_str)


def read_file_bin(filename):
    """ Read content of given file as byte string and return it """

    file_bytes = bytes()
    with open(filename, "rb") as f:
        while True:
            cur_bytes = f.read(READ_CHUNK_SIZE)
            if len(cur_bytes) > 0:
                file_bytes += cur_bytes
            else:
                break

            if len(file_bytes) > MAX_FILE_SIZE:
                err_msg = "error: file too large to embed, max %.3f GB (%d bytes)" % (MAX_FILE_SIZE / 2**30, MAX_FILE_SIZE)
                error(err_msg)
    return file_bytes


def write_steg_byte(byte, embed_pos, carrier):
    """ Write hidden byte to carrier using the given embedding information """

    for i in range(0, 8):
        bit = (byte & 2**i) >> i
        x, y, c = embed_pos.popleft()
        orig_rgb = carrier.getpixel((x, y))
        new_val = (orig_rgb[c] & 0xFE) | bit

        if c == 0:  # red
            carrier.putpixel((x,y), (new_val, orig_rgb[1], orig_rgb[2]))
        elif c == 1:  # green
            carrier.putpixel((x,y), (orig_rgb[0], new_val, orig_rgb[2]))
        elif c == 2:  # blue
            carrier.putpixel((x,y), (orig_rgb[0], orig_rgb[1], new_val))


def read_steg_byte(embed_pos, carrier):
    """ Read hidden byte from carrier using the given embedding information """

    byte = 0
    for i in range(0, 8):
        x, y, c = embed_pos.popleft()
        bit = carrier.getpixel((x, y))[c] & 0x01
        byte += bit * 2**i
    return struct.pack("B", byte)


def compute_embed_postitions_hide(carrier, total_embed_count):
    """ Compute the image positions to use for embedding """

    # create deque to hold all positions
    embed_pos = deque(maxlen=total_embed_count)

    # create randomized lists of x, y and color indices
    carrier_width, carrier_height = carrier.size
    x_idx, y_idx, c_idx = list(range(carrier_width)), list(range(carrier_height)), list(range(3))
    random.shuffle(x_idx)
    random.shuffle(y_idx)
    random.shuffle(c_idx)
    
    # iterate over randomized color indices, x coordinates and y coordinates
    for c in c_idx:
        for x in x_idx:
            print_progress(len(embed_pos), total_embed_count, "positions")
            for y in y_idx:
                if len(embed_pos) >= total_embed_count:
                    break
                
                # store embedding positions as combination of coordinates and color chanel
                embed_pos.append((x, y, c))
            if len(embed_pos) >= total_embed_count:
                break
        if len(embed_pos) >= total_embed_count:
            break
    print_progress(total_embed_count, total_embed_count, "positions")
    return embed_pos


def hide(carrier, secretfile):
    """ Hide the contens of the given secretfile inplace inside the given carrier image """

    # read binary content of secret file
    cprint("[+] Parsing secret file", color="green")
    secret_bytes = read_file_bin(secretfile)

    # compress the secret file bytes
    cprint("[+] Compressing secret file", color="green")
    carrier_width, carrier_height = carrier.size
    max_embed_size = carrier_width * carrier_height * 3 / 8  # in byte; '* 3', b/c RGB
    secret_bytes = zlib.compress(secret_bytes, level=9)
    if len(secret_bytes) + 4 > max_embed_size:  # + 4 bytes for size field
        err_msg = "error: compressed secret file too large to fit into carrier image, "
        err_msg += "max %f MB" % ((max_embed_size-4) / 2**20)
        error(err_msg)

    # compute the positions inside the carrier at which to embed data
    cprint("[+] Computing embedding positions", color="green")
    size_arr = struct.pack("<I", len(secret_bytes))
    secret_bytes = size_arr + secret_bytes
    total_byte_count = len(secret_bytes)
    total_embed_count = total_byte_count * 8
    embed_pos = compute_embed_postitions_hide(carrier, total_embed_count)

    # embed the compressed secret bytes using the embedding positions
    cprint("[+] Hiding secret file in carrier image", color="green")
    for i, byte in enumerate(secret_bytes):
        if i % PRINT_PROGRESS_FREQ == 0:
            print_progress(i, total_byte_count, "bytes")
        write_steg_byte(byte, embed_pos, carrier)
    print_progress(total_byte_count, total_byte_count, "bytes")


def compute_embed_postitions_reveal(carrier):
    """ Recompute the image positions used for embedding """
    
    # create randomized lists of x, y and color indices
    carrier_width, carrier_height = carrier.size
    x_idx, y_idx, c_idx = list(range(carrier_width)), list(range(carrier_height)), list(range(3))
    random.shuffle(x_idx)
    random.shuffle(y_idx)
    random.shuffle(c_idx)

    # start with 32 positions to read the 4 length bytes at the beginning
    embed_pos = deque(maxlen=32)
    total_embed_count = None

    # iterate over randomized color indices, x coordinates and y coordinates
    for c in c_idx:
        for x in x_idx:
            if total_embed_count:
                print_progress(len(embed_pos), total_embed_count, "positions")
            for y in y_idx:
                embed_pos.append((x, y, c))

                if total_embed_count and len(embed_pos) >= total_embed_count:
                    break

                # after reading the first 4 bytes, extract the number of embedded secret bytes
                if not total_embed_count and len(embed_pos) == 32:
                    size = bytes()
                    for i in range(0, 4):
                        size += read_steg_byte(embed_pos, carrier)
                    total_embed_count = struct.unpack("<I", size)[0] * 8
                    embed_pos = deque(maxlen=total_embed_count)
                    print_progress(len(embed_pos), total_embed_count, "positions")

            if total_embed_count and len(embed_pos) >= total_embed_count:
                break
        if total_embed_count and len(embed_pos) >= total_embed_count:
            break
    print_progress(total_embed_count, total_embed_count, "positions")

    return embed_pos


def reveal(carrier, password):
    """ Reveal the secret inside the carrier using the given password """

    # recmompute embedding positions
    cprint("[+] Recomputing embedding positions", color="green")
    embed_pos = compute_embed_postitions_reveal(carrier)
    
    # use embedding positions to read compressed secret byte by byte
    cprint("[+] Extracting secret file from carrier image", color="green")
    secret_bytes = bytes()
    size = len(embed_pos) // 8
    for i in range(0, size):
        if i % PRINT_PROGRESS_FREQ == 0:
            print_progress(i, size, "bytes")
        secret_bytes += read_steg_byte(embed_pos, carrier)
    print_progress(size, size, "bytes")

    # decompress secret bytes
    cprint("[+] Decompressing secret file", color="green")
    secret_bytes = zlib.decompress(secret_bytes)

    return secret_bytes


def error(msg, parser=None):
    """ Output the given error message and exit """

    cprint(msg, color="red")
    if parser:
        parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    # print banner
    title = "|===== LSB Image Steganography Tool (by Dustin Born) =====|"
    cprint("-"*len(title), color="yellow")
    cprint(title, color="yellow")
    cprint("-"*len(title), color="yellow")

    # setup argument parser
    parser = argparse.ArgumentParser(description="A tool for LSB image steganography.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hide", action="store_true", help="invoke hiding utility")
    group.add_argument("-R", "--reveal", action="store_true", help="invoke revealing utility")

    parser.add_argument("-c", "--carrier", required=True, help="the image file that carries or will carry the secret file")
    parser.add_argument("-s", "--secretfile", help="the file that will be hidden inside the carrier")
    parser.add_argument("-o", "--outfile", required=True, help="the name of either the revealed secret file (with '-R') or the carrier containing the embedded secret file (with '-H')")
    parser.add_argument("-p", "--password", help="the password to use for hiding or revealing (usage of this argument is insecure; if no password is supplied, you will be prompted)")

    # parse and validate arguments
    args = parser.parse_args()
    if args.hide and not args.secretfile:
        print("%s: error: you need to specify a secret file to hide with -s/--secretfile\n" % sys.argv[0], file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    if not os.path.isfile(args.carrier):
        err_msg = "error: carrier file '%s' does not exist\n" % args.carrier
        error(err_msg, parser)
    if args.secretfile and not os.path.isfile(args.secretfile):
        err_msg = "error: secret file '%s' does not exist\n" % args.secretfile
        error(err_msg, parser)

    # get password
    password = args.password
    if not password:
        password = getpass.getpass("Password:")

    # make similar passwords differ more from each other via hashing
    password = hashlib.sha512(password.encode("utf-8")).hexdigest()

    # seed PRNG
    random.seed(password)

    # check that carrier can be opened by Pillow
    try:
        cprint("[+] Parsing carrier image", color="green")
        carrier = Image.open(args.carrier)
    except:
        err_msg = "error: cannot open carrier image file '%s'" % args.carrier
        error(err_msg)

    # hide / reveal
    if args.hide:
        hide(carrier, args.secretfile)
        outfile = args.outfile
        if not outfile.endswith(".png"):
            outfile = outfile + ".png"
        cprint("[+] Exporting carrier image with hidden secret file as '%s'" % outfile, color="green")
        carrier.save(outfile, "PNG")
    elif args.reveal:
        secret_bytes = reveal(carrier, password)
        cprint("[+] Restoring secret file as '%s'" % args.outfile, color="green")
        with open(args.outfile, "wb") as f:
            f.write(secret_bytes)

    cprint("[+] Done", color="yellow")
