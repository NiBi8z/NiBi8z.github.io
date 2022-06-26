---
title: "CryptoHack - Signing Server"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','sign']
titlepage: true
toc: true
toc-own-page: true
---

### Instructions : 

My boss has so many emails he's set up a server to just sign everything automatically. He also stores encrypted messages to himself for easy access. I wonder what he's been saying.

Connect at nc socket.cryptohack.org 13374

Challenge files:
  - 13374.py


13374.py : 

```python
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener



class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my signing server. You can get_pubkey, get_secret, or sign.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_pubkey':
            return {"N": hex(N), "e": hex(E) }

        elif your_input['option'] == 'get_secret':
            secret = bytes_to_long(SECRET_MESSAGE)
            return {"secret": hex(pow(secret, E, N)) }

        elif your_input['option'] == 'sign':
            msg = int(your_input['msg'], 16)
            return {"signature": hex(pow(msg, D, N)) }

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13374)
```

### Solution : 

This server is pretty strange... We can get the rsa public key, get a "secret message" and sign an hexadecimal string. The sign option is basically calculating message <sup>d</sup> mod n. The sign function will simply decipher the text previously entered.

"get_secret" is calculating secret<sup>e</sup> mod n. So, "get_secret" give us a ciphered text and the sign function allow us to decipher a text ? We can ask the sign function to give us the secret text and decipher it with the sign function !

Using python : 

```python
from pwn import * # pip install pwntools
import json
from Crypto.Util.number import long_to_bytes

r = remote('socket.cryptohack.org', 13374, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)



r.recvline()
json_send({"option":"get_secret"})
secret=json_recv()["secret"][2:]

json_send({"option":"sign","msg":secret})

signature=json_recv()["signature"][2:]

sign_to_int=int(signature,16)

print(long_to_bytes(sign_to_int))
```
