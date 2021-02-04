import pefile

def uint32(i):
    return i & 0xffffffff

def ror_uint32(i, bits):
    i = uint32(i >> bits) | uint32(i << (32 - bits))
    return i

def hash_module(string):
    acc = 0
    for c in string:
        acc = ror_uint32(acc, 0xd)
        inc = ord(c)
        if ord('`') < inc:
            acc -= 0x20
        acc = uint32(acc + inc)
        acc = ror_uint32(acc, 0xd)
    acc = ror_uint32(acc, 0xd)
    acc = ror_uint32(acc, 0xd)
    return acc

def hash_symbol(string):
    acc = 0
    for c in string:
        acc = ror_uint32(acc, 0xd)
        acc = uint32(acc + ord(c))
    acc = ror_uint32(acc, 0xd)
    return acc

def hash(module_name, symbol_name):
    return uint32(hash_module(module_name) + hash_symbol(symbol_name))

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

hashes = {}
for dll in dlls:
    pe = pefile.PE(filename)
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.name:
            h = hash(filename, symbol.name)
            hashes[filename.replace('.', '_') + '__' + symbol.name] = hex(h)

result = "enum MODULE_EXPORT_HASH {\n"
result += "    " + ',\n    '.join('{} = {}'.format(k, v) for k, v in hashes.items())
result += "\n};"

print(result)
