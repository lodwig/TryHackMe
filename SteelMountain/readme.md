# Steel Mountain (10.10.104.116)

### Task 1  Introduction
+ Who is the employee of the month?`Bill harper`

### Task 2  Initial Access
+ Scan the machine with nmap. What is the other port running a web server on?`8080`
+ Take a look at the other web server. What file server is running? `Rejetto http file server`
+ What is the CVE number to exploit this file server?`2014-6287`
+ Use Metasploit to get an initial shell. What is the user flag? `b04763b6fcf51fcd7c13abc7db4fd365`

### Task 3  Privilege Escalation
+ Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability?`AdvancedSystemCareService9`
+ What is the root flag?`9af5f314f57607c00fd09803a587db80`

### Task 4  Access and Escalation Without Metasploit
+ *Format is "powershell -c "command here"* `powershell -c Get-Service`

