#include <Windows.h>

extern void SetWinAddrs(void *rtl, ULONGLONG etwp, void *f);
extern void Starter(void);

void *_memcpy(void *dest, const void *src, size_t n) {
  char *d = (char *)dest;
  const char *s = (const char *)src;
  while (n--) {
    *d++ = *s++;
  }
  return dest;
}
void print(char s[], int len) {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD charsWritten;
  WriteConsole(hConsole, s, len, &charsWritten, NULL);
}

void Starter_() { Starter(); }

typedef int (*pRtlExitUserProcess)(NTSTATUS status);
typedef BOOL (*pVirtualProtect)(PVOID addr, SIZE_T size, DWORD flags,
                                DWORD *oldprotect);

int Fail(NTSTATUS status) {
  print("The password is NOT correct, you have failed!\n", 46);
  return 0;
}
int Success(NTSTATUS status) {
  print("You got it!\n", 12);
  return 0;
}
// type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;

DWORD Verification() {
  unsigned char rtl_payload[13] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0xff, 0xe0, 0x90};
  HMODULE ntdll = GetModuleHandleA("C:\\Windows\\System32\\ntdll.dll");
  HMODULE kernel32 = GetModuleHandleA("C:\\Windows\\System32\\kernel32.dll");

  unsigned char **key = GetProcAddress(ntdll, "RtlUserThreadStart");
  ULONGLONG *status = GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID RtlExitUserProcess = GetProcAddress(ntdll, "RtlExitUserProcess");
  DWORD oldprotect;
  VirtualProtect(RtlExitUserProcess, 13, PAGE_EXECUTE_READWRITE, &oldprotect);
  int flag = 1;
  unsigned char answerKey[] = {
      66, 2, 81,  10, 94, 83, 5,   53, 45, 42, 121, 53, 46,  0, 121, 59, 38,
      51, 9, 197, 10, 9,  8,  213, 0,  42, 29, 7,   25, 197, 6, 196, 121};
  for (int i = 0; i < 32; ++i) {
    if ((*key)[i] != ((answerKey[i] ^ (57 + i)) - i)) {
      flag = 0;
    }
  }
  PVOID f = flag ? Success : Fail;
  ULONGLONG EtwpShutdownPrivateLoggers =
      (ULONGLONG)((LONGLONG)RtlExitUserProcess +
                  *((DWORD *)((ULONGLONG)RtlExitUserProcess + 9))) +
      13;
  //__debugbreak();
  SetWinAddrs(RtlExitUserProcess, EtwpShutdownPrivateLoggers, f);
  *((ULONGLONG **)(rtl_payload + 2)) = (ULONGLONG *)Starter_;
  _memcpy(RtlExitUserProcess, rtl_payload, 13);
  DWORD p2;
  VirtualProtect(RtlExitUserProcess, 13, oldprotect, &p2);
  return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    Verification();
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
