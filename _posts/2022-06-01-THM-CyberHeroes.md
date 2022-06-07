---
title: "THM - CyberHeroes "
author: NiBi
lang: "en"
categories : ['Try Hack Me']
tags : ['CTF', 'THM','easy','javascript']
titlepage: true
toc: true
toc-own-page: true
---

# Enumeration 

## Nmap
Let's start by using nmap to see which ports are open

```shell
└─$ nmap -A 10.10.125.139
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-07 03:21 EDT
Nmap scan report for 10.10.125.139
Host is up (0.91s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ac:fb:4b:1a:17:50:8a:b8:81:14:77:5c:15:aa:6b:41 (RSA)
|   256 cb:52:a6:0a:50:5c:01:d9:09:16:d9:81:fe:96:27:bf (ECDSA)
|_  256 f1:c9:a2:ff:5a:f0:d6:9f:f0:ba:3d:69:7c:e1:4e:23 (ED25519)
80/tcp open  http    Apache httpd 2.4.48 ((Ubuntu))
|_http-title: CyberHeros : Index
|_http-server-header: Apache/2.4.48 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.22 seconds
```

## Port 80


```shell
└─$ dirsearch -u http://10.10.125.139


  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.125.139/_22-06-07_03-23-36.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-06-07_03-23-36.log

Target: http://10.10.125.139/
                            
[03:23:54] 200 -    1KB - /assets/                                               
[03:23:54] 301 -  315B  - /assets  ->  http://10.10.125.139/assets/         
[03:23:56] 200 -    3KB - /changelog.txt                                    
[03:24:06] 200 -    6KB - /index.html                                       
[03:24:09] 200 -    6KB - /login.html                                                                     
                                                                             
Task completed
```

Nothing here :/ 

In the source code of the login page we have this

```html
 <main id="main">

    <section id="hero" class="d-flex flex-column justify-content-center align-items-center">
      <div class="hero-container">
        <br><br><br><br>
        <div class="">
          <div class="form">
          <h4 id="flag"></h4>
            <form id="todel"class="">
              <div class="section-title">
                <h2>Login</h2>
                <h4>Show your hacking skills and login to became a CyberHero ! :D</h4>
              </div>
              <input type="text" id="uname" placeholder="username"/>
              <input type="password" id="pass" placeholder="password"/>
            </form>
            <button id="rm" onclick="authenticate()">login</button>
          </div>
        </div>
      </div>
    </section>

  </main>

  <script>
    function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
    }
  </script>
```

When we press the login button, the function authenticate() is launched.

Take a look at this function.
```javascript
function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
    }
```

So, the code check if the username is "h3ck3rBoi" and the password is "RevereString("54321@terceSrepuS")".
RevereString() is just reversing a string...
If we reverse "54321@terceSrepuS" we have "SuperSecret@12345"

By using "h3ck3rBoi" as username and "SuperSecret@12345" as password, we get the flag

Done.
 