# The Return of the Yeti
## https://tryhackme.com/jr/adv3nt0fdbopsjcap
+ What's the name of the WiFi network in the PCAP? `FreeWifiBFC`
+ What's the password to access the WiFi network? `Christmas`
    - Convert pcapng to pcap`tshark -F pcap -r VanSpy.pcapng -w evidence.pcap`
    - Add wap key to wireshark to decrypt and check stream on 1005 
    - Copy pfx file from base64 and decode to pfx file.
    - Trying to extract hash from pfx`pfx2pfx2john lmr.pfx > pfx_hash` 
    - Cracking hash brute the password `john --format=pfx pfx_hash`
    - 
+ What suspicious tool is used by the attacker to extract a juicy file from the server? `mimikatz`
+ What is the case number assigned by the CyberPolice to the issues reported by McSkidy?