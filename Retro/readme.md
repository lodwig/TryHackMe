# Retro 

### Task 1  Pwn
+ A web server is running on the target. What is the hidden directory which the website lives on?
+ [50] user.txt `3b99fbdc6d430bfb51c72c651a261927`
+ [100] root.txt `7958b569565d7bd88d10c6f22d1c4063`

### Enumeration 
+ Scan with nmap `nmap -sV -Pn -vv 10.10.211.112 -oN nmap_log`
```bash
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
```
+ Scan Web Directory `gobuster dir -u http://10.10.211.112/ -w ~/HackTools/directory-list-2.3-medium.txt`
```bash
===============================================================
2024/02/06 21:18:41 Starting gobuster in directory enumeration mode
===============================================================
/retro                (Status: 301) [Size: 150] [--> http://10.10.211.112/retro/]
```
+ Enumerate on content and got something on comment from wade
+ Try login to Remote Desktop and got the user.txt

### Escalation
+ Look at the trash have a `hhupd.exe` run as administrator
+ Open with Internet Explorer and wait for error 
+ After error 