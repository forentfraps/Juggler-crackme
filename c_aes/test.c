#include <Windows.h>

#include <stdio.h>
int main() {
  printf("Loaded GCC! %lu\n", LoadLibraryA("aes_dll_GCC.dll"));
  getchar();
  printf("Loaded! %lu\n", LoadLibraryA("aes_dll.dll"));
  getchar();
}
