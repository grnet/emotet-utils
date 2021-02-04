#!/usr/bin/env python3

import struct
import sys


def extract_c2_socket_addresses(stream):
    socket_addresses = []
    while True:
        *ipv4_octets, port = struct.unpack('<BBBBHxx', stream.read(8))
        if all(octet == 0 for octet in ipv4_octets) and port == 0:
            break
        ipv4 = '%d.%d.%d.%d' % tuple(reversed(ipv4_octets))
        socket_addresses.append((ipv4, port))
    return socket_addresses


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('%s <filename> <offset>' % sys.argv[0])
        sys.exit(1)
    filename = sys.argv[1]
    offset = int(sys.argv[2], 0)
    with open(filename, 'rb') as f:
        f.seek(offset)
        socket_addresses = extract_c2_socket_addresses(f)
    for ipv4, port in socket_addresses:
        print('%s:%s' % (ipv4, port))
