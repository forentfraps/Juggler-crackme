nasm -fwin64  -o hook.obj hook.asm 
cl /c /O2 /MT /W4 /GS- verification.c /Fo:verification.obj /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.39.33519\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
link /DLL /ENTRY:DllMain /NODEFAULTLIB /OUT:mod2_nocrt.dll verification.obj hook.obj /SUBSYSTEM:CONSOLE /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.39.33519\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" Kernel32.lib User32.lib
del verification.obj hook.obj
python .\encrypter.py
