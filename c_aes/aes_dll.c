#include "aes_lib/aes.h"
#include <Windows.h>
#include <synchapi.h>
#include <winnt.h>

extern void stub();
extern void EventLoopCallback();

HANDLE console = NULL;

unsigned char *keyArrayParam = NULL;
ULONGLONG volatile *statusParam = NULL;
PVOID *workAddressParam = NULL;

DWORD WINAPI EventLoop(LPVOID _) {
  DWORD trash = 0;
  unsigned char *keyArray = keyArrayParam;
  ULONGLONG volatile *status = statusParam;
  PVOID *workAddress = workAddressParam;
  while (*status != 0) {
  }
  *workAddress = (PVOID)1;

  while (1) {
    if (*status != 0) {
      if (*status == 2) {

        // WriteConsole(console, "[C] STOPPED ENCRYPT\n", 22, &trash, NULL);
        return 0;
      }

      // WriteConsole(console, "[C] DECRYPTED BLOCK\n", 22, &trash, NULL);
      Decrypt(*workAddress, keyArray);
      *status = 0;
    }
  }
  return 0;
}

typedef NTSTATUS(NTAPI *TPALLOCWORK)(PTP_WORK *ptpWrk,
                                     PTP_WORK_CALLBACK pfnwkCallback,
                                     PVOID OptionalArg,
                                     PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI *TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI *TPRELEASEWORK)(PTP_WORK);

void TpAllocCreateThread() {
  void *ntdll = GetModuleHandleW(L"ntdll.dll");
  TPALLOCWORK TpAllocWork = (TPALLOCWORK)GetProcAddress(ntdll, "TpAllocWork");
  TPPOSTWORK TpPostWork = (TPPOSTWORK)GetProcAddress(ntdll, "TpPostWork");
  TPRELEASEWORK TpReleaseWork =
      (TPRELEASEWORK)GetProcAddress(ntdll, "TpReleaseWork");
  PTP_WORK wrk = NULL;
  TpAllocWork(&wrk, (PTP_WORK_CALLBACK)EventLoopCallback, EventLoop, NULL);
  TpPostWork(wrk);
  TpReleaseWork(wrk);
}
extern void unlock_thread(void *ptr);

DWORD WINAPI Initialise() {
  // No point in checking, since if anything fails segfault is
  // the most graceful exit anyone can hope for.
  // Everything will just collapse, gracefully, obviously
  HMODULE ntdll = GetModuleHandleA("C:\\Windows\\System32\\ntdll.dll");
  ULONGLONG volatile *status =
      (ULONGLONG *)GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID *workAddress = (PVOID)GetProcAddress(ntdll, "RtlUserThreadStart");
  unsigned char volatile *masterKey = HeapAlloc(GetProcessHeap(), 0, 16);
  // Here is the 1024 buffer for the zig_keymaster
  unlock_thread(*(void **)(GetModuleHandleW(0)));
  asm volatile("mov %0, %%rax\n\t"
               "2:\n\t"
               "jmp 2b\n\t"
               ".long 0x48c48348\n\t"
               "pop %%rbp\n\t"
               "ret\n\t"
               ".fill 2048, 1, 0xc3\n\t"
               :
               : "r"(masterKey)
               : "%rax", "%r10", "%rcx", "%r8", "%r9");

  unsigned char *keyArray = HeapAlloc(GetProcessHeap(), 0, 176);
  KeyScheduler(masterKey, keyArray);
  keyArrayParam = keyArray;
  statusParam = status;
  workAddressParam = workAddress;
  DWORD trash = 0;
  // WriteConsole(console, "[C] INIT COMPLETE\n", 18, &trash, NULL);

  TpAllocCreateThread();

  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    Initialise();
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
