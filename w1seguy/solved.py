#!/usr/bin/env python3
import socket
import string
abjad = string.ascii_letters + string.digits
HOST = "10.10.233.181"
PORT = 1337
FLAG_FORMAT = "THM{"
FLAG_END = "}"
FLAG_HEX = "54484d7b"
def xor_4_char(enc_flag): 
    result = ""
    for index in range(0,len(enc_flag[:8]), 2):
        a = int(enc_flag[index:index+2], 16)
        b = int(FLAG_HEX[index:index+2], 16)
        c = a ^ b
        result += chr(c)
    return result

def bruteForce(enc_flag, keys):
    idx = 0
    result = ""
    for index in range(0,len(enc_flag), 2):
        _flag = int(enc_flag[index:index+2], 16) ^ ord(keys[idx])
        idx += 1
        if(idx == 5):
            idx = 0
        result += chr(_flag)
    return result

try:
    isfound = False
    check = ""
    while check.lower() != "n":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        q = s.recv(1024)
        s.recv(1024)
        query  = q.decode().splitlines()[0]
        enc_flag = query.split("1: ")[1].strip()
        keys = xor_4_char(enc_flag)
        for a in abjad:
            key_brute = keys + a
            posible_flag = bruteForce(enc_flag, key_brute)
            if(posible_flag[-1] == FLAG_END):
                s.send(key_brute.encode())
                print(f"[+] Flag 1: {posible_flag}")
                dodol = s.recv(4096).decode()
                print(f"[+] {dodol}")
                isfound = True
                break
        if(isfound):
            check = input("Continue? [ Y | n ] ")
    s.close()
            
except Exception as err:
    print("Ada Error", err)
