
uint __fastcall hashLowercase(WCHAR *input)

{
  uint curLowercased;
  WCHAR cur;
  uint accumulator;
  
  accumulator = 0;
  cur = *input;
  while (cur != 0) {
    curLowercased = (uint)(ushort)*input;
    if ((0x40 < curLowercased) && (curLowercased < 0x5b)) {
      curLowercased = curLowercased + 0x20;
    }
    input = (WCHAR *)((ushort *)input + 1);
    accumulator = curLowercased + accumulator * 0x1003f;
    cur = *input;
  }
  return accumulator;
}


