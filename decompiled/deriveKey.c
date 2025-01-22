
undefined4 __cdecl deriveKey(char *passphrase,int passphraseSize,uint i)

{
  ulonglong uVar1;
  int j;
  uint passIdx;
  uint accumulator;
  uint tmp;
  
  tmp = i;
  decryptionKey = (byte *)malloc(0x25e);
  passIdx = 0;
  j = 0;
  do {
    decryptionKey[j] = (byte)j;
    j = j + 1;
  } while (j < 0x25e);
  i = 0;
  accumulator = 0;
  *(undefined *)tmp = 0;
  *(undefined *)(tmp + 1) = 0;
  do {
    accumulator = ((uint)decryptionKey[i] + accumulator + (byte)passphrase[passIdx & 0xff]) % 0x25e
                  & 0xff;
    swap(decryptionKey + i,decryptionKey + accumulator);
    uVar1 = (ulonglong)((passIdx & 0xff) + 1);
    passIdx = (uint)((longlong)uVar1 % (longlong)passphraseSize);
    i = i + 1;
  } while ((int)i < 0x25e);
  return (int)((longlong)uVar1 / (longlong)passphraseSize);
}
