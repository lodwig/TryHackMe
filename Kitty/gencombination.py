#!/usr/bin/env python3

pwd = "l0ng_liv3_kitty"
pwdlist = []

tmp=[]
for x in pwd:
    if(x.isnumeric()):
        continue
    else:
        tmp.append(pwd.replace(x,x.upper()))

p=open('pass.txt','w')
for x in tmp:
    p.write("%s\n" % x)
p.close()
