#include "aes_lib/aes.h"
#include <Windows.h>
int EventLoop(unsigned char *keyArray, ULONGLONG *status, PVOID *workAddress) {
  while (1) {
    while (*((ULONGLONG *)status) == 0) {
      Sleep(20);
    }
    if (*status == 2) {
      return 0;
    }
    Decrypt(*workAddress, keyArray);
  }
  *status = 0;
  return 0;
}

DWORD WINAPI Initialise() {
  // No point in checking, since if anything fails segfault is
  // the most graceful exit anyone can hope for.
  // Everything will just collapse, gracefully, obviously
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  ULONGLONG *status = GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID *workAddress = GetProcAddress(ntdll, "DbgUiRemoteBreakin");
  unsigned char *masterKey = HeapAlloc(GetProcessHeap(), 0, 16);
  for (int i = 0; i < 16; ++i) {
    masterKey[i] = ((i ^ (i + 127)) | 60) - 60;
  }
  unsigned char *keyArray = HeapAlloc(GetProcessHeap(), 0, 176);
  KeyScheduler(masterKey, keyArray);
  while (((ULONGLONG *)status) != 0) {
    Sleep(20);
  }
  EventLoop(keyArray, status, workAddress);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    MessageBoxA(NULL, "Ok!", "Bebra!", MB_OK);
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
