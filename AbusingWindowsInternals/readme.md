# Abusing Windows Internals

## Task 1  Introduction
+ Learning Objectives
    - Understand how internal components are vulnerable
    - Learn how to abuse and exploit Windows Internals vulnerabilities
    - Understand mitigations and detections for the techniques
    - Apply techniques learned to a real-world adversary case study

## Task 2  Abusing Processes
+ Identify a PID of a process running as THM-Attacker to target. Once identified supply the PID as an argument to execute shellcode-injector.exe located in the Injectors directory on the desktop. `No Answer Needed`
+ What flag is obtained after injecting the shellcode? `THM{1nj3c710n_15_fun!}`

## Task 3  Expanding Process Abuse
+ Identify a PID of a process running as THM-Attacker to target. Supply the PID and executable name as arguments to execute hollowing-injector.exe located in the injectors directory on the desktop. `No Answer Needed`
+ What flag is obtained after hollowing and injecting the shellcode?`THM{7h3r35_n07h1n6_h3r3}`
```bash
C:\Users\THM-Attacker\Desktop\Injectors>hollowing-injector.exe 3340
[+] Created victim process
        [*] PID 1908
[+] Replacement executable opened
        [*] Size 103424 bytes
[+] Read replacement executable into memory
        [*] In current process at 0x00860000
[+] Obtained context from victim process's primary thread
        [*] Victim PEB address / EBX = 0x006d1000
        [*] Victim entry point / EAX = 0x00d136d0
[+] Extracted image base address of victim process
        [*] Address: 0x00d10000
[+] Hollowed out victim executable via NtUnmapViewOfSection
        [*] Utilized base address of 0x00d10000
[+] Replacement image metadata extracted
        [*] replacementImageBaseAddress = 0x00400000
        [*] Replacement process entry point = 0x00001268
[+] Allocated memory in victim process
        [*] pVictimHollowedAllocation = 0x00d10000
        [*] Headers written into victim process
        [*] Section .text written into victim process at 0x00d11000
                [*] Replacement section header virtual address: 0x00001000
                [*] Replacement section header pointer to raw data: 0x00000400
        [*] Section .rdata written into victim process at 0x00d12000
                [*] Replacement section header virtual address: 0x00002000
                [*] Replacement section header pointer to raw data: 0x00001200
        [*] Section .data written into victim process at 0x00d13000
                [*] Replacement section header virtual address: 0x00003000
                [*] Replacement section header pointer to raw data: 0x00001e00
        [*] Section .rsrc written into victim process at 0x00d14000
                [*] Replacement section header virtual address: 0x00004000
                [*] Replacement section header pointer to raw data: 0x00002000
        [*] Section .reloc written into victim process at 0x00d2c000
                [*] Replacement section header virtual address: 0x0001c000
                [*] Replacement section header pointer to raw data: 0x00019200
[+] Victim process entry point set to replacement image entry point in EAX register
        [*] Value is 0x00d11268
[+] Resuming victim process primary thread...
[+] Cleaning up
```

## Task 4  Abusing Process Components
+ Identify a PID of a process running as THM-Attacker to target. Supply the PID as an argument to execute thread-injector.exe located in the Injectors directory on the desktop. `No Answer Needed`
+ What flag is obtained after hijacking the thread?`THM{w34p0n1z3d_53w1n6}`

## Task 5  Abusing DLLs
+ dentify a PID and name of a process running as THM-Attacker to target. Supply the name and malicious DLL found in the Injectors directory as arguments to execute dll-injector.exe located in the Injectors directory on the desktop. `No Answer Needed`
+ What flag is obtained after injecting the DLL?`THM{n07_4_m4l1c10u5_dll}`

## Task 6  Memory Execution Alternatives
+ What protocol is used to execute asynchronously in the context of a thread?`asynchronous procedure call`
+ What is the Windows API call used to queue an APC function?`QueueUserAPC`
+ Can the void function pointer be used on a remote process? (y/n)`n`

## Task 7  Case Study in Browser Injection and Hooking
+ What alternative Windows API call was used by TrickBot to create a new user thread?`RtlCreateUserThread`
+ Was the injection techniques employed by TrickBot reflective? (y/n)`y`
+ What function name was used to manually write hooks?`write_hook_iter`

## Task 8  Conclusion
+ Read the above and continue learning! `No Answer Needed`