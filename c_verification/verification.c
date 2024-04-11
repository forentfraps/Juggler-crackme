#include "lib_hook/winhook.h"
#include <stdio.h>

typedef int (*pRtlExitUserProcess)(NTSTATUS status);
int Fail(NTSTATUS status) {
  pRtlExitUserProcess f;
  printf("The password is NOT correct, you have failed!\n");
  return f(status);
}
int Success(NTSTATUS status) {
  pRtlExitUserProcess f;
  printf("You got it!\n");
  return f(status);
}

DWORD Verification() {
  HookInfo h;
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  unsigned char **key = GetProcAddress(ntdll, "DbgUiRemoteBreakin");
  ULONGLONG *status = GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID RtlExitUserProcess = GetProcAddress(ntdll, "RtlExitUserProcess");
  int flag = 1;
  unsigned char answerKey[] = {
      66, 2, 81,  10, 94, 83, 5,   53, 45, 42, 121, 53, 46,  0, 121, 59, 38,
      51, 9, 197, 10, 9,  8,  213, 0,  42, 29, 7,   25, 197, 6, 196, 121};
  for (int i = 0; i < 32; ++i) {
    if ((*key)[i] != (answerKey[i] ^ (57 + i) - i)) {
      flag = 0;
      break;
    }
  }
  PVOID f = flag ? Success : Fail;
  InstallHook(RtlExitUserProcess, f, &h);
  return 0;
}
// s[i] ^ (i + (57 ^i))
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
