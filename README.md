## HellsHall: Another Way of Fetching Clean Syscalls
*HellsHall* is a combo between [HellGate](https://github.com/am0nsec/HellsGate) and the *indirect syscalls* principle.  

<br>


## HOW DOES IT WORK
First *HellsHall* checks if the *syscall address* is hooked or not, and try to get the syscall number, by checking the presence of the following bytes; `0x4C, 0x8B, 0xD1, 0xB8`, that represents `mov r10,rcx && mov eax, SSn`, which should start every syscall.

[Hell'Gate](https://github.com/am0nsec/HellsGate) stops at this point, and just get the Syscall SSn (Syscall Number), to use it **directly**, as a syscall being called from outside of the address space of the `ntdll.dll`. This can be used to detect such syscalls; ex: [Detecting Manual Syscalls from User Mode](https://winternl.com/detecting-manual-syscalls-from-user-mode/)  +  [Detecting Direct Syscalls with Frida](https://passthehashbrowns.github.io/detecting-direct-syscalls-with-frida)

*HellsHall* However, will search for a `syscall` instruction near the address of the syscall function, then it will save this *`syscall` instruction's address* to a global variable, that will get jumped to later on, instead of executing this instruction directly from the asm implementation. This will cause the syscall function to be executed from inside of `ntdll.dll` address space, the only difference is that it is unhooked.

One can add [TartarusGate](https://github.com/trickster0/TartarusGate) logic, to further enhance this technique.


## HellsGate 
![image](https://user-images.githubusercontent.com/111295429/210207400-594383fb-158f-415c-9e3a-2d3d43198644.png)


<br>

## HellsHall
![image](https://user-images.githubusercontent.com/111295429/210207411-f6dca820-dbfe-4c87-bb33-60e0d036bd73.png)


<br>

## Profit
Bypassing The Below EDR using [This Hell'sHall Implementation](https://github.com/Maldev-Academy/HellHall/blob/main/Hell'sHall-Clang%26NoCrt.zip) That is Using `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, and `NtCreateThreadEx` syscalls with a `RWX section` 

![image](https://user-images.githubusercontent.com/111295429/210299245-d366566a-0e14-4622-8bb0-91fd645a9d2e.png)


<br>


Authors:
- ORCA (@ORCx41)
- Mr.D0x (@mrd0x)

