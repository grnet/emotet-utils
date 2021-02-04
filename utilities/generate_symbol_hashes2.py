#!/usr/bin/env python3

dlls = [
    'advapi32.dll',
    'crypt32.dll',
    'kernel32.dll',
    'ntdll.dll',
    'shell32.dll',
    'shlwapi.dll',
    'wininet.dll',
    'urlmon.dll',
    'userenv.dll',
    'wtsapi32.dll'
]

def hash(string):
    ret = 0
    for c in string:
        ret = ord(c) + ret * 0x1003f & 0xffffffff
    return ret

# Module name hashes

module_hashes = {}
for filename in dlls:
    h = hash(filename.lower()) ^ 0x7f212706
    module_hashes[filename] = hex(h)

result = "enum MODULE_HASH {\n"
result += "    " + ',\n    '.join('{} = {}'.format(k.replace('.', '_'), v) for k, v in module_hashes.items())
result += "\n};"

print(result)

# Export symbol hashes

import pefile

export_hashes = {}
for filename in dlls:
    pe = pefile.PE(filename)
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.name:
            h = hash(symbol.name) ^ 0x4d07de46
            export_hashes[symbol.name] = hex(h)

result = "enum EXPORT_HASH {\n"
result += "    " + ',\n    '.join('{} = {}'.format(k, v) for k, v in export_hashes.items())
result += "\n};"

print(result)

