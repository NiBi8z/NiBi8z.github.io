---
title: "CryptoHack - JSON in JSON"
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
We've explored how flawed verification can break the security of JWTs, but it can sometimes be possible to exploit the code to sign unexpected data in the first place.

Play at http://web.cryptohack.org/json-in-json

Challenge contributed by sublevel_1157
```

The web app source code: 

```python
import json
import jwt # note this is the PyJWT module, not python-jwt


FLAG = ?
SECRET_KEY = ?


@chal.route('/json-in-json/authorise/<token>/')
def authorise(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"] == "True":
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


@chal.route('/json-in-json/create_session/<username>/')
def create_session(username):
    body = '{' \
              + '"admin": "' + "False" \
              + '", "username": "' + str(username) \
              + '"}'
    encoded = jwt.encode(json.loads(body), SECRET_KEY, algorithm='HS256')
    return {"session": encoded}

```

### Solution : 

First, i noticed that unlike previous challenges, we do not have any misconfiguration (e.g: Double encoding, etc.). The only one entry point we have is the "username" field.

Our username is directly written into json and encoded as JWT payload.

Here is the json code.
```json
 '{' \
              + '"admin": "' + "False" \
              + '", "username": "' + str(username) \
              + '"}'
```

What can we write as username to become admin ?

If we inject "admin":"True" the value of admin will be overwritten. 

Let's try differents payloadx.

I succeed with this one : admin","admin":"True

At the end we have for json : 

{' \
              + '"admin": "' + "False" \
              + '", "username": "' + str(<span style="color:green">admin","admin":"True</span>) \
              + '"}'


Json encoded will be : 

```json
{
    "admin": "False",
    "username": "admin",
    "admin":"True"
}
```

We can generate our token and send it to get the flag.