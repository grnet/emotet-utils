
LPCWSTR __fastcall decryptWideString(uint *encryptedData)

{
  uint *puVar1;
  uint plaintextLength;
  void *module1;
  HANDLE hHeap;
  void *module2;
  LPCWSTR plaintext;
  uint decrypted4Chars;
  LPCWSTR plaintextPtr;
  uint ciphertextLength;
  uint i;
  uint *ciphertext;
  ushort decrypted2HiChars;
  uint key;
  
  key = *encryptedData;
  plaintextLength = encryptedData[1] ^ key;
  ciphertextLength = plaintextLength + 1;
  ciphertext = encryptedData + 2;
  if ((ciphertextLength & 3) != 0) {
    ciphertextLength = (ciphertextLength & 0xfffffffc) + 4;
  }
  if (GetProcessHeapPtr == (GetProcessHeap *)0x0) {
    module1 = (void *)findModuleByHash(kernel32_dll);
    GetProcessHeapPtr = (GetProcessHeap *)findModuleExportByHash((byte *)module1,GetProcessHeap);
  }
  hHeap = (*GetProcessHeapPtr)();
  if (HeapAllocPtr == (HeapAlloc *)0x0) {
    module2 = (void *)findModuleByHash(kernel32_dll);
    HeapAllocPtr = (HeapAlloc *)findModuleExportByHash((byte *)module2,HeapAlloc);
  }
  plaintext = (LPCWSTR)(*HeapAllocPtr)(hHeap,8,ciphertextLength * 2);
  if (plaintext != (LPCWSTR)0x0) {
    i = 0;
    puVar1 = (uint *)((int)ciphertext + (ciphertextLength & 0xfffffffc));
    ciphertextLength = (uint)((int)puVar1 + (3 - (int)ciphertext)) >> 2;
    if (puVar1 < ciphertext) {
      ciphertextLength = 0;
    }
    plaintextPtr = plaintext;
    if (ciphertextLength != 0) {
      do {
        decrypted4Chars = *ciphertext ^ key;
        ciphertext = ciphertext + 1;
        i = i + 1;
        *plaintextPtr = (ushort)decrypted4Chars & 0xff;
        plaintextPtr[1] = (ushort)(decrypted4Chars >> 8) & 0xff;
        decrypted2HiChars = (ushort)(decrypted4Chars >> 0x10);
        plaintextPtr[2] = decrypted2HiChars & 0xff;
        plaintextPtr[3] = decrypted2HiChars >> 8;
        plaintextPtr = plaintextPtr + 4;
      } while (i < ciphertextLength);
    }
    plaintext[plaintextLength] = L'\0';
  }
  return plaintext;
}


