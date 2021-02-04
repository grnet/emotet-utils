
void __cdecl decryptResource(byte *resource,dword size,byte *iv)

{
  byte bVar1;
  byte bVar2;
  ulonglong uVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  uint uVar7;
  int i;
  
  i = 0;
  bVar4 = *iv;
  bVar5 = iv[1];
  if (0 < (int)size) {
    uVar6 = (uint)bVar4;
    uVar7 = (uint)bVar5;
    do {
      uVar3 = (ulonglong)(uVar6 + 1) % 0x25e;
      uVar6 = (uint)uVar3 & 0xff;
      bVar4 = (byte)uVar3;
      uVar3 = (ulonglong)(decryptionKey[uVar6] + uVar7) % 0x25e;
      uVar7 = (uint)uVar3 & 0xff;
      bVar5 = (byte)uVar3;
      swap(decryptionKey + uVar6,decryptionKey + uVar7);
      bVar1 = decryptionKey[uVar7];
      bVar2 = decryptionKey[uVar6];
      ShowWindow((HWND)0x0,0);
      resource[i] = resource[i] ^
                    decryptionKey[(byte)((ulonglong)((uint)bVar1 + (uint)bVar2) % 0x25e)];
      i = i + 1;
    } while (i < (int)size);
  }
  *iv = bVar4;
  iv[1] = bVar5;
  return;
}


