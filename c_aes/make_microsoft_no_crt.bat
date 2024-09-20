@echo off

REM Compile C files with Microsoft cl
cl /c /W4 /MT /GS- /O1 aes_dll.c /Fo:aes_dll.obj /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.39.33519\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
cl /c /W4 /MT /GS- /O1 aes_lib/aes.c /Fo:aes.obj /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.39.33519\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
nasm -fwin64 -o stub.obj stub.asm
REM Assemble the assembly file with nasm
nasm -f win64 aes_lib/fast.asm -o fast.obj

REM Link the object files into a DLL
link /DLL /ENTRY:DllMain /OUT:aes_dll_nocrt.dll /NODEFAULTLIB /SUBSYSTEM:CONSOLE stub.obj aes_dll.obj aes.obj fast.obj /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.41.34120\lib\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.39.33519\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" Kernel32.lib User32.lib msvcrt.lib

REM Clean up the intermediate object files
del aes_dll.obj aes.obj fast.obj
