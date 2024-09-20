# Juggler crackme

This is my best attempt at making a crackme. Currently its biggest challenge is the anti-debugging part, meaning, if you find the key processing logic you are practically done. 

## Building the project

You will require:
 - GCC
 - Visual Studio build tools (cl and lib)
 - rust compiler
 - zig
 - nasm
 - python 3
 - strip (this is optional)
 - ability to edit 1 file

The file requiring edit is in c_verification under the name of make_microsoft_nocrt.bat

Edit all the paths, pointing to visual studio related stuff, or try your luck, may be we are using the same version

After you have all that you clone the repo and run the build.bat

```shell
git clone https://github.com/forentfraps/Juggler-crackme.git --depth=1
cd Juggler-crackme
.\build.bat
```
### *I suggest you try solving it before you scroll down and see all of the design ideas and spoilers*

I update the crackme overtime, adding new functionality. All releases from V2 (including the V2) are fully funcitonal.

## Architectural overview
```
+----------------------+----------------------+----------------------+----------------------+
| rust main thread     | zig key deriver      | rust warden          | c aes verification   |
+----------------------+----------------------+----------------------+----------------------+
|                      |                      |                      |                      |
| Loads zig key        |                      |                      |                      |
| deriver -------------|-> Enters infinite    |                      |                      |
|                      | loop                 |                      |                      |
| Begins loading c aes |                      |                      |                      |
| verification (pauses)|                      |                      |                      |
| Unlocks zig key      |                      |                      |                      |
| deriver ------------>| Receives unlock,     |                      |                      |
|                      | modifies rust main   |                      |                      |
|                      | thread     |         |                      |                      |
| Context modified <---|------------/         |                      |                      |
|                      | Unlocks main thread  |                      |                      |
|                      |                |     |                      |                      |
| Receives unlock <----|----------------/     |                      |                      |
|                      |                      |                      |                      |
| Continues loading c  |                      |                      |                      |
| aes verification ----|----------------------|----------------------|-> Starts running     |
| Loads rust warden ---|--------------------->| Starts running       |                      |
| Passes data to rust  |                      |                      |                      |
| warden --------------|--------------------->| Receives data        |                      |
|                      |                      | Passes data to c aes |                      |
|                      |                      | verification --------|--------------------->|
|                      |                      |                      | Receives data        |
|                      |                      |                      | Decrypts data        |
|                      |                      |                      | Passes decrypted data|
|                      |                      |                      | back to rust warden  |
|                      |                      | Receives decrypted   |                    | |
|                      |                      | data <---------------|--------------------/ |
|                      |                      | Passes decrypted data|                      |
|                      |                      | back to rust main    |                      |
|                      |                      | thread       |       |                      |
| Receives decrypted   |                      |              |       |                      |
| data <---------------|----------------------|--------------/       |                      |
| Loads data into      |                      |                      |                      |
| memory and executes  |                      |                      |                      |
+----------------------+----------------------+----------------------+----------------------+

```
## Anti-Debug tricks

### Making the static analysis unbearable
- Swapping the header of embedded dll's to BMP format 
- Stripping it from labels
- Littering with with `hide!` and `fake_exit!` asm macros:
    - hide!

      The big idea is that you cannot disassemble after a call to a special function, because it increments the return address by one. And the reason for this increment is a junk byte 0x9a after the call, which screws up the disassembly.
      ```asm
      call appendByte2Rip
      db 0x9a
      ;here the execution resumes
      ```
      where appndByte2Rip does just what is says
      ```
      appendByte2Rip:
          pop r11
          add r11, 1
          jmp r11
      ```
    - fake_exit!

      Here the idea is to make it seem that the function ends. We extract current IP, put it on the stack and then return, effectively ending the function, whearas in reality the execution continues past the `ret`.
      In the macro I added a bit more logic and junk data.
      ```asm
      call label
      label:
      pop rax
      add rax, 29
      xor r9, 0xf8145 ; useless calculation, making the compiler's life more difficult, since I clobber one more register
      push rax
      ret 
      ;13 bytes of junk data
      db 13 dup(0xcc)
      ;here the execution resumes
      ```

This is all easily avoidable when stepping through funcions, so the last anti-static defense is encrypting the key verification logic



### Dynamic Anti-Debugging tricks
 - Each load is a runtime Reflective DLL Load
 - Thread locking and unlocking is just one thread entering an infinite loop like:
   ```
    label:
    jmp label
   ```
   And when the second thread is unlocking that infinite loop thread, it finds this loop, and just fills it with nops  with thread safe lock prefix like so:
   ```
    mov rax, 0x9090909090909090
    lock xchg rax, [addr of loop]
   ```
 - Data between the `warden` and `c aes verification` is passed via RtlUserThreadStart and DbgBreakPoint, so the buffer is literally the first bytes of these functions. The idea behind this decision is that so when you remotely try to suspend the process, it tries to create a new thread and dies instantly, or it just fails to start one, either is fine. 
 - The whole point of the zig thread is that it puts a NtContinueEx syscall in the main thread, which jumps over 2048 junk bytes. The NtContinueEx detaches Intel Pin, rendering any codecoverage plugins and tools useless (without manual modification, you have to check [rdx] manually and jump - adjust rip - manually)
 - Read of the user provided string is done via NtReadVirtualMemory, a kernel mode function. This is in place to avoid triggering and hardware breakpoints on read/write.
 - The same NtReadVirtualMemory is used to put a hook on RtlExitUserProcess to display Win/Lose messages
 - Most of the threads are created through TpAllocWork/TpPostWork/TpReleaseWork, more on that could be read: https://0xdarkvortex.dev/hiding-in-plainsight/


## How to solve it

When designing this, I tried to patch every approach I would take, so this section is more like a TODO list for the future:
 - Hooking/Blocking VirtualProtect/VirtualAlloc and looking at what is happening at the memory regions.
   
   I think this is solved with manual syscalls, since pintool is out of the picture (thanks to NtContinueEx), good luck trying to find which memory is what
 - Since the logic overall is pretty obscure,after hooking juicy GetModuleHandle/GetProcAddress or aforementioned VirtualProtect/VirtualAlloc stack trace could be observed and backtracked.

   This could be solved in moving all these juicy calls outside, via TpAllocWork. Where the cleanest stack trace will yeild no useful info

  - Once the encrypted payload and the key are extracted + it is clear that the algo is simple AES, there are no more obstacles

    Since the AES implementation is my own, I could change up the constants, making it oh so more fun to reverse this hellfile, but I think this will remain as-is, since the main challenge is circumvention of anti-debug measures.




