nasm -fwin64 -o hook.o hook.asm
gcc -c verification.c -o verification.o -ffreestanding -nostdlib -fpic
gcc -shared verification.o hook.o -o mod2_nocrt.dll -nostdlib -nostartfiles -luser32 -lkernel32 -fpic -Wl,--entry,DllMain
