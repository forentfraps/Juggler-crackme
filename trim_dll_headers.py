with open("sample1.bmp", "rb") as f:
    cool_header = f.read()[:40]
with open("c_aes\\aes_dll_nocrt.dll", "rb") as f:
    aes_dll = f.read()

with open("zig_key_derivation\\zig-out\\bin\\zig_key_derivation.dll", "rb") as f:
    zig_dll = f.read()

aes_dll = cool_header + aes_dll[40:]
zig_dll = cool_header + zig_dll[40:]

with open("c_aes\\aes_dll_nocrt.dll", "wb") as f:
    f.write(aes_dll)

with open("zig_key_derivation\\zig-out\\bin\\zig_key_derivation.dll", "wb") as f:
    f.write(zig_dll)   
