gcc -c verification.c -o verification.o
gcc -shared verification. -o mod2.dll
del verification.o
python .\encrypter.py
