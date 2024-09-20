gcc -c aes_dll.c -o aes_dll.o -O3
gcc -c aes_lib/aes.c -o aes.o -O3 -w
nasm -fwin64 aes_lib/fast.asm -o fast.o
nasm -fwin64 stub.asm -o stub.o
nasm -fwin64 ../zig_key_derivation/src/thread_safe_memcpy.asm -o tsm.o
gcc -shared aes_dll.o aes.o stub.o fast.o tsm.o -o aes_dll_nocrt.dll -O3
del *.o
