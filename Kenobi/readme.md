# Kenobi (10.10.110.227)
### Task 1  Deploy the vulnerable machine
+ Scan the machine with nmap, how many ports are open? `7`

### Task 2  Enumerating Samba for shares
+ Using the nmap command above, how many shares have been found?`3`
+ Once you're connected, list the files on the share. What is the file can you see? `log.txt`
+ What port is FTP running on? `21`
+ What mount can we see? `/var`

### Task 3  Gain initial access with ProFtpd
+ What is the version? `1.3.5`
+ How many exploits are there for the ProFTPd running? `4`
+ What is Kenobi's user flag (/home/kenobi/user.txt)?`d0b0f3f53b6caa532a83915e19224899`

### Task 4  Privilege Escalation with Path Variable Manipulation
+ What file looks particularly out of the ordinary? `/usr/bin/menu`
+ Run the binary, how many options appear?`3`
+ What is the root flag (/root/root.txt)?`177b3cd8562289f37382721c28381f02`