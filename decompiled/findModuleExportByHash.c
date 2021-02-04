
byte * __fastcall findModuleExportByHash(byte *module,EXPORT_HASH hash)

{
  uint h;
  HMODULE forwardingModule;
  byte *functionAddress;
  byte *pbVar1;
  uint i;
  IMAGE_EXPORT_DIRECTORY *exportTable;
  byte *local_108;
  char abStack260 [224];
  byte *local_24;
  IMAGE_DATA_DIRECTORY *exportDataDirectory;
  DWORD *addressOfNamesOffset;
  uint lfanewOffset;
  DWORD *addressOfFunctionsOffset;
  char c;
  DWORD addressOfNameOrdinalsOffset;
  int exportTableOffset;
  
  lfanewOffset = *(uint *)(module + 0x3c);
  i = 0;
  exportTableOffset = *(int *)(module + lfanewOffset + 0x78);
  addressOfFunctionsOffset = *(DWORD **)(module + exportTableOffset + 0x1c);
  exportTable = (IMAGE_EXPORT_DIRECTORY *)(module + exportTableOffset);
  addressOfNamesOffset = (DWORD *)exportTable->AddressOfNames;
  addressOfNameOrdinalsOffset = exportTable->AddressOfNameOrdinals;
  if (exportTable->NumberOfNames != 0) {
    do {
      h = hashString((char *)(module + *(int *)(module + (int)(addressOfNamesOffset + i))));
      if ((h ^ 0x4d07de46) == hash) {
        functionAddress =
             module + *(int *)(module + (int)(addressOfFunctionsOffset +
                                             *(ushort *)
                                              (module + i * 2 + addressOfNameOrdinalsOffset)));
                    /* Each entry in the export address table is a field that uses one of two
                       formats in the following table. If the address specified is not within the
                       export section (as defined by the address and length that are indicated in
                       the optional header), the field is an export RVA, which is an actual address
                       in code or data. Otherwise, the field is a forwarder RVA, which names a
                       symbol in another DLL. */
        if ((functionAddress < exportTable) ||
           ((byte *)((int)&exportTable->Characteristics +
                    *(int *)((int)(module + lfanewOffset + 0x78) + 4)) <= functionAddress)) {
          return functionAddress;
        }
        pbVar1 = (byte *)abStack260;
        c = *functionAddress;
        goto joined_r0x00404411;
      }
      i = i + 1;
    } while (i < exportTable->NumberOfNames);
  }
  return (byte *)0x0;
joined_r0x00404411:
  if (c == 0) {
LAB_00404426:
    if (GetModuleHandleAPtr == (GetModuleHandleA *)0x0) {
      pbVar1 = (byte *)findModuleByHash(kernel32_dll);
      GetModuleHandleAPtr = (GetModuleHandleA *)findModuleExportByHash(pbVar1,GetModuleHandleA);
    }
    forwardingModule = (*GetModuleHandleAPtr)(abStack260);
    if (forwardingModule == (HMODULE)0x0) {
      if (LoadLibraryAPtr == (LoadLibraryA *)0x0) {
        pbVar1 = (byte *)findModuleByHash(kernel32_dll);
        LoadLibraryAPtr = (LoadLibraryA *)findModuleExportByHash(pbVar1,LoadLibraryA);
      }
      forwardingModule = (*LoadLibraryAPtr)((LPCSTR)&local_108);
      if (forwardingModule == (HMODULE)0x0) {
        return (byte *)0x0;
      }
    }
    i = hashString((char *)(functionAddress + 1));
    pbVar1 = findModuleExportByHash((byte *)forwardingModule,i ^ 0x4d07de46);
    return pbVar1;
  }
  if (c == 0x2e) {
    *pbVar1 = 0;
    goto LAB_00404426;
  }
  functionAddress = functionAddress + 1;
  *pbVar1 = c;
  pbVar1 = pbVar1 + 1;
  c = *functionAddress;
  goto joined_r0x00404411;
}

