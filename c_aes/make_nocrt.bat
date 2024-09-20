gcc -c aes_dll.c -o aes_dll.o -O3
gcc -c aes_lib/aes.c -o aes.o -O3
nasm -f win64 aes_lib/fast.asm -o fast.o
gcc -shared aes_dll.o aes.o fast.o -o aes_dll_nocrt.dll -O3
del *.o
