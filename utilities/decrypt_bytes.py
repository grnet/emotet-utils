#!/usr/bin/env python3

import itertools
import sys


def decrypt_bytes(stream):
    xor_key = int.from_bytes(stream.read(4), byteorder='little')
    encrypted_length = int.from_bytes(stream.read(4), byteorder='little')

    plaintext_length = encrypted_length ^ xor_key

    ciphertext_length = plaintext_length >> 2
    if plaintext_length & 3 != 0:
        ciphertext_length += 1

    ciphertext = stream.read(ciphertext_length * 4)

    plaintext = b''
    for encrypted_bytes in map(bytes, itertools.zip_longest(*([iter(ciphertext)] * 4), fillvalue=0)):
        encrypted_int = int.from_bytes(encrypted_bytes, byteorder='little')
        decrypted_int = encrypted_int ^ xor_key
        decrypted_bytes = int.to_bytes(decrypted_int, 4, byteorder='little')
        plaintext += decrypted_bytes

    plaintext = plaintext[:plaintext_length]
    return plaintext


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('%s <filename> <offset>' % sys.argv[0])
        sys.exit(1)
    filename = sys.argv[1]
    offset = int(sys.argv[2], 0)
    with open(filename, 'rb') as f:
        f.seek(offset)
        plaintext = decrypt_bytes(f)
    sys.stdout.buffer.write(plaintext)
