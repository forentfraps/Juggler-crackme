cd zig_key_derivation && zig build -Doptimize=ReleaseFast && cd ..\c_verification && .\make_microsoft_nocrt.bat && cd ..\c_aes && .\make.bat && cd .. && python trim_dll_headers.py && cargo build --release && strip target\release\juggler.exe