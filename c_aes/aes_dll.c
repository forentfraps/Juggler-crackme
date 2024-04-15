#include "aes_lib/aes.h"
#include <Windows.h>
#include <synchapi.h>

extern void stub();

int __declspec(noinline)
    EventLoop(unsigned char *keyArray, ULONGLONG volatile *status,
              PVOID *workAddress) {
  while (1) {
    if (*status != 0) {
      if (*status == 2) {
        return 0;
      }
      Decrypt(*workAddress, keyArray);
      *status = 0;
    }
  }
  return 0;
}

DWORD WINAPI Initialise() {
  // No point in checking, since if anything fails segfault is
  // the most graceful exit anyone can hope for.
  // Everything will just collapse, gracefully, obviously
  HMODULE ntdll = GetModuleHandleA("C:\\Windows\\System32\\ntdll.dll");
  ULONGLONG volatile *status = GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID *workAddress = GetProcAddress(ntdll, "RtlUserThreadStart");
  unsigned char *masterKey = HeapAlloc(GetProcessHeap(), 0, 16);
  for (unsigned char i = 0; i < 16; ++i) {
    masterKey[i] = ((i ^ (i + 127)) | 60) - 60;
  }
  unsigned char *keyArray = HeapAlloc(GetProcessHeap(), 0, 176);
  KeyScheduler(masterKey, keyArray);
  while (*status != 0) {
  }
  *workAddress = (PVOID)1;

  EventLoop(keyArray, status, workAddress);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    CreateThread(NULL, 0, Initialise, NULL, 0, NULL);
    break;

  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    if (lpvReserved != NULL) {
      break;
    }
    break;
  }
  return TRUE;
}
