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
    ```powershell
    mimikatz(commandline) # crypto::certificates /systemstore:LOCAL_MACHINE /store:"Remote Desktop" /export
    * System Store  : 'LOCAL_MACHINE' (0x00020000)
    * Store         : 'Remote Desktop'

    0. INTERN-PC
        Subject  : CN=INTERN-PC
        Issuer   : CN=INTERN-PC
        Serial   : ffb1d93a1df0324cadd5e13f3f9f1b51
        Algorithm: 1.2.840.113549.1.1.1 (RSA)
        Validity : 11/22/2023 9:18:19 PM -> 5/23/2024 9:18:19 PM
        Hash SHA1: a0168513fd57577ecc0204f01441a3bd5401ada7
        Key Container  : TSSecKeySet1
        Provider       : Microsoft Enhanced Cryptographic Provider v1.0
        Provider type  : RSA_FULL (1)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft Enhanced Cryptographic Provider v1.0
        |Key Container : TSSecKeySet1
        |Unique name   : f686aace6942fb7f7ceb231212eef4a4_c5d2b969-b61a-4159-8f78-6391a1c805db
        |Implementation: CRYPT_IMPL_SOFTWARE ; 
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO
        Public export  : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.der'
        Private export : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx'

        PS C:\Users\Administrator> [Convert]::ToBase64String([IO.File]::ReadAllBytes("/users/administrator/LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx"))
        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
        ```
+ What is the case number assigned by the CyberPolice to the issues reported by McSkidy?