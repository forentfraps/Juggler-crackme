#include <Windows.h>

void print(char s[], int len) {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD charsWritten;
  WriteConsole(hConsole, s, len, &charsWritten, NULL);
}

typedef int (*pRtlExitUserProcess)(NTSTATUS status);
int Fail(NTSTATUS status) {
  print("The password is NOT correct, you have failed!\n", 46);
  return 0;
}
int Success(NTSTATUS status) {
  print("You got it!\n", 12);
  return 0;
}

DWORD Verification() {
  HMODULE ntdll = GetModuleHandleA("C:\\Windows\\System32\\ntdll.dll");
  unsigned char **key = GetProcAddress(ntdll, "RtlUserThreadStart");
  ULONGLONG *status = GetProcAddress(ntdll, "DbgBreakPoint");
  PVOID RtlExitUserProcess = GetProcAddress(ntdll, "RtlExitUserProcess");

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
  if (flag) {
    print("You got it!\n", 12);
    return 0;
  } else {

    print("The password is NOT correct, you have failed!\n", 46);
    return 0;
  }
  print("IH\n", 3);
  //  asm(".byte 0xcc");
  print("FI\n", 3);
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
