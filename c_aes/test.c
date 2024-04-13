#include "aes_lib/aes.h"
#include <Windows.h>
#include <stdio.h>

void printblock(unsigned char *b) {
  for (int i = 0; i < 16; ++i) {
    printf("%d ", b[i]);
  }
  printf("\n");
  return;
}

int main() {
  unsigned char *masterKey = HeapAlloc(GetProcessHeap(), 0, 16);
  for (int i = 0; i < 16; ++i) {
    masterKey[i] = ((i ^ (i + 127)) | 60) - 60;
  }
  unsigned char *keyArray = HeapAlloc(GetProcessHeap(), 0, 176);
  KeyScheduler(masterKey, keyArray);
  unsigned char b[16] = {0};
  printblock(b);
  Encrypt(b, keyArray);
  printblock(b);
  Decrypt(b, keyArray);
  printblock(b);
}
