#ifndef _winhook_h_
#define _winhook_h_

#include <Windows.h>

#include "Zydis.h"

#define CALL 0xd0
#define JMP 0xe0
#define LEN_IMPLANT 13

#define GET_VICTIM_ADDR(addr) asm volatile("movq %%rsi, %0" : : "m"(*(addr)))

#define GVA GET_VICTIM_ADDR

typedef struct hook_info {
  LPVOID catalyst;
  int sz;
  unsigned char bytes[32];
} HookInfo;

int InstallHook(void *pf_victim, void *pf_hook, HookInfo *_hook_info);
int RemoveHook(void *pf_victim, HookInfo *h);

#endif
