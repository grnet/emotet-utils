
void * __fastcall resolveImportByHash(MODULE_EXPORT_HASH target_hash)

{
  uint *addressOfNames;
  uint accumulator1;
  uint curNameIndex;
  char *c_ptr;
  _LDR_DATA_TABLE_ENTRY *dataTableEntry;
  uint i;
  uint accumulator2;
  int in_FS_OFFSET;
  uint nameOffset;
  byte *dllBase;
  UNICODE_STRING *baseDllNamePtr;
  UNICODE_STRING *baseDllNamePtr2;
  char c;
  int exportDirectoryOffset;
  
                    /* FS:[0x30] Linear address of Process Environment Block (PEB) 
                       PEB:[0xc] LoaderData (PPEB_LDR_DATA)
                       LDR:[0xc] InLoadOrderModuleList */
  dataTableEntry = *(_LDR_DATA_TABLE_ENTRY **)(*(int *)(*(int *)(in_FS_OFFSET + 0x30) + 0xc) + 0xc);
  do {
    do {
      do {
        dllBase = (byte *)dataTableEntry->DllBase;
        if (dllBase == (byte *)0x0) {
          return (byte *)0x0;
        }
        baseDllNamePtr = &dataTableEntry->BaseDllName;
        accumulator1 = 0;
        baseDllNamePtr2 = &dataTableEntry->BaseDllName;
        dataTableEntry = (_LDR_DATA_TABLE_ENTRY *)(dataTableEntry->InLoadOrderLinks).Flink;
                    /* DLL:[0x3c] = e_lfanew
                       PE:[0x78] = DataDirectory[0] */
        exportDirectoryOffset = *(int *)(dllBase + *(int *)(dllBase + 0x3c) + 0x78);
      } while (exportDirectoryOffset == 0);
                    /* BaseDllName MaximumLength (because of endianess) */
      curNameIndex = *(uint *)baseDllNamePtr2 >> 0x10;
      i = 0;
      if (curNameIndex != 0) {
        do {
          c = *(char *)(i + (int)baseDllNamePtr->Buffer);
          accumulator1 = accumulator1 >> 0xd | accumulator1 << 0x13;
          if ('`' < c) {
                    /* convert to uppercase */
            accumulator1 = accumulator1 - 0x20;
          }
          accumulator1 = accumulator1 + (int)c;
          i = i + 1;
        } while (i < curNameIndex);
      }
      curNameIndex = 0;
                    /* ExportDirectory:[0x20] AddressOfNames */
      addressOfNames = (uint *)(dllBase + *(int *)(dllBase + exportDirectoryOffset + 0x20));
                    /* ExportDirectory:[0x18] NumberOfNames */
    } while (*(uint *)(dllBase + exportDirectoryOffset + 0x18) == 0);
    do {
      nameOffset = *addressOfNames;
      accumulator2 = 0;
      addressOfNames = addressOfNames + 1;
      c_ptr = (char *)(dllBase + nameOffset);
      do {
        accumulator2 = (accumulator2 >> 0xd | accumulator2 << 0x13) + (int)*c_ptr;
        c = *c_ptr;
        c_ptr = c_ptr + 1;
      } while (c != '\0');
      if (accumulator2 + accumulator1 == target_hash) {
                    /* resolves the function address based on the nameOrdinal
                       ExportDirectory:[0x1c] AddressOfFunctions
                       ExportDirectory:[0x24] AddressOfNameOrdinals */
        return dllBase + *(int *)(dllBase +
                                 *(int *)(dllBase + exportDirectoryOffset + 0x1c) +
                                 (uint)*(ushort *)
                                        (dllBase +
                                        *(int *)(dllBase + exportDirectoryOffset + 0x24) +
                                        curNameIndex * 2) * 4);
      }
      curNameIndex = curNameIndex + 1;
                    /* ExportDirectory:[0x18] NumberOfNames */
    } while (curNameIndex < *(uint *)(dllBase + exportDirectoryOffset + 0x18));
  } while( true );
}


