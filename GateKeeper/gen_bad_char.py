#!/usr/bin/env python3
from colorama import init as colorama_init
from colorama import Fore
colorama_init()
bad_char = open('badchars.txt','r').read()
badchar_bytes=""
for b in bad_char.split(" "):
    badchar_bytes+="\\x" + b
print(f"[+] Bad Chars: {Fore.LIGHTYELLOW_EX}{badchar_bytes}")
print(f"{Fore.LIGHTGREEN_EX}[+] Mona: {Fore.LIGHTYELLOW_EX}!mona bytearray -b \"{badchar_bytes}\"")

payload="" 
for x in range(1, 256):
    bc = "{:02x}".format(x)
    if(bc not in bad_char.strip()):
        payload+="\\x" + "{:02x}".format(x)

print(f"{Fore.LIGHTGREEN_EX}[+] Payload: {Fore.LIGHTYELLOW_EX}\n{payload}")
