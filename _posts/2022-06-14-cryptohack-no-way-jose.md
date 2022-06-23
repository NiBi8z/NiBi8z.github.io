---
title: "CryptoHack - No way jose"
author: NiBi
lang: "en"
categories : ['Crypto']
tags : ['Challenge', 'Cryptohack','JWT','JSON','crypto','web']
titlepage: true
toc: true
toc-own-page: true
---


In this challenge we are suppose to exploit a code based on JSON WEB TOKENS.

as explained on the "token application" challenge : JavaScript Object Signing and Encryption (JOSE) is a framework specifying ways to securely transmit information on the internet. It's most well-known for JSON Web Tokens (JWTs), which are used to authorise yourself on a website or application. JWTs typically do this by storing your "login session" in your browser after you have authenticated yourself by entering your username and password. In other words, the website gives you a JWT that contains your user ID, and can be presented to the site to prove who you are without logging in again


In this challenge we have to use this python code :

```python
import base64
import json
import jwt # note this is the PyJWT module, not python-jwt


SECRET_KEY = ?
FLAG = ?


@chal.route('/no-way-jose/authorise/<token>/')
def authorise(token):
    token_b64 = token.replace('-', '+').replace('_', '/') # JWTs use base64url encoding
    try:
        header = json.loads(base64.b64decode(token_b64.split('.')[0] + "==="))
    except Exception as e:
        return {"error": str(e)}

    if "alg" in header:
        algorithm = header["alg"]
    else:
        return {"error": "There is no algorithm key in the header"}

    if algorithm == "HS256":
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except Exception as e:
            return {"error": str(e)}
    elif algorithm == "none":
        try:
            decoded = jwt.decode(token, algorithms=["none"], options={"verify_signature": False})
        except Exception as e:
            return {"error": str(e)}
    else:
        return {"error": "Cannot decode token"}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


@chal.route('/no-way-jose/create_session/<username>/')
def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': False}, SECRET_KEY, algorithm='HS256')
    return {"session": encoded}
```

We have a text box to get our token with our username and another box to decode our token.

First, we have to understand how JWT works.

Here is an exemple of JWT : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOmZhbHNlfQ.yRhbtEnBab1UfHM95yP6Ukz3EQrQqP6lwZFcqwvKwjg"


This string is divided in 3 parts with a dot

#### First part

"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".


This first part is the header. This string is base64url encoded. You can decode it online and you get :
```json
{
    "typ":"JWT",
    "alg":"HS256"
}
``` 

So we see that the signature (third part) will be hashed with HS256 algorithm.

#### Second part

"eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOmZhbHNlfQ"

Like the first part, this part is base64url encoded so we can decode it online and we get :

```json

{
    "username":"admin",
    "admin":false
}

```

#### Third part

"yRhbtEnBab1UfHM95yP6Ukz3EQrQqP6lwZFcqwvKwjg"

This part is the signature.

To compute this signature, we have to concatenate the base64url encoded header with the base64url encoded payloadwith "." between them and hash this string with the algorithm specified in the header with a secret key.

The server will be able to know if the signature is correct because it knows the secret key so it can compute the signature itself and compare it with the given one.


#### Solving this challenge


Now we know how JWT works.

In our payload we have

```json

{
    "username":"admin",
    "admin":false
}

```

The problem is we can't change "admin":false to "admin":true because if we change the payload the base64url payload with change and the signature won't be the same as one provided by the server.

Let's take a look to the given source code.

```python
 if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
```

Here, we notice that we need to have "admin" as username.
We also notice that we need to have "admin":true in our payload.

As we said previously we can change our payload but the server will reject it because of the signature.

```python
    if algorithm == "HS256":
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except Exception as e:
            return {"error": str(e)}
    elif algorithm == "none":
        try:
            decoded = jwt.decode(token, algorithms=["none"], options={"verify_signature": False})
        except Exception as e:
            return {"error": str(e)}
    else:
        return {"error": "Cannot decode token"}
```

But here we have a problem !

So, if the alorithm in the header is "HS256" (like in our case), the token will be decoded thanks to secret key. It's impossible to change data because of this secret key.

But, if algorithm is set to "none", the payload will be decoded without checking the signature : 
```python
decoded = jwt.decode(token, algorithms=["none"], options={"verify_signature": False})
```

It is exactly what we want !

We can change the algorithm to "none". Encode the header in base64url. Change admin to true. Encode the payload in base64url and write anything as signature because it won't be checked.

Let's do it !

#### Exploit

As we said previously we change the algorithm to none : 

```json
{
    "typ":"JWT",
    "alg":"none"
}
``` 

We encode this in base64url :

```text
YGBganNvbg0Kew0KICAgICJ0eXAiOiJKV1QiLA0KICAgICJhbGciOiJub25lIg0KfQ0KYGBgIA
```

Next, we change our payload with admin:true instead of admin:false : 

```json
{

    "username":"admin",
    "admin":true
}
```

We encode it in base64url :

```text
ew0KDQogICAgInVzZXJuYW1lIjoiYWRtaW4iLA0KICAgICJhZG1pbiI6dHJ1ZQ0KfQ
```

We do not need to change the signature because it won't be checked.

Now, we concatenate our parts with a dot between each part and we have : 

```base64
YGBganNvbg0Kew0KICAgICJ0eXAiOiJKV1QiLA0KICAgICJhbGciOiJub25lIg0KfQ0KYGBgIA.ew0KDQogICAgInVzZXJuYW1lIjoiYWRtaW4iLA0KICAgICJhZG1pbiI6dHJ1ZQ0KfQ.yRhbtEnBab1UfHM95yP6Ukz3EQrQqP6lwZFcqwvKwjg
```

Voila, we have our own JWT. The server will decode the payload and see that the algoritm is "none" so it will read our payload without checking the signature !