gcc -c verification.c -o verification.o
gcc -shared verification.o lib_hook/winhook.o -o mod2.dll
del verification.o
python .\encrypter.py
