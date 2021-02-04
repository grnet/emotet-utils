
void * __fastcall findModuleByHash(DLL_HASH hash)

{
  uint c_copy;
  LIST_ENTRY *head;
  PWSTR c_ptr;
  TEB *teb;
  int elm3;
  WCHAR c;
  WCHAR mixed_case_char;
  _LDR_DATA_TABLE_ENTRY *list_entry;
  uint accumulator;
  
  head = &teb->ProcessEnvironmentBlock->LoaderData->InLoadOrderModuleList;
  list_entry = (_LDR_DATA_TABLE_ENTRY *)head->Flink;
  while( true ) {
    if (list_entry == (_LDR_DATA_TABLE_ENTRY *)head) {
      return (void *)0x0;
    }
    c_ptr = (list_entry->BaseDllName).Buffer;
    accumulator = 0;
    c = *c_ptr;
    while (c != L'\0') {
      c_copy = (uint)(ushort)*c_ptr;
                    /* uppercase to lowercase */
      if ((0x40 < c_copy) && (c_copy < 0x5b)) {
        c_copy = c_copy + 0x20;
      }
      c_ptr = (PWSTR)((ushort *)c_ptr + 1);
      accumulator = c_copy + accumulator * 0x1003f;
      c = *c_ptr;
    }
    if ((accumulator ^ 0x7f212706) == hash) break;
    list_entry = (_LDR_DATA_TABLE_ENTRY *)(list_entry->InLoadOrderLinks).Flink;
  }
  return list_entry->DllBase;
}


