---
title: "CryptoHack - Export Grade"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'AES','crypto','Diffie-Hellman','MITM','Discrete logarithm']
titlepage: true
toc: true
toc-own-page: true
---

#### Instructions : 

Alice and Bob are using legacy codebases and need to negotiate parameters they both support. You've man-in-the-middled this negotiation step, and can passively observe thereafter. How are you going to ruin their day this time?

Connect at nc socket.cryptohack.org 13379

#### Solution : 

First step, we intercept this from Alice : 

```text
Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
```

I did some tests and Bob will always chose the DH with the highest number. 
I tried all possibilites and i understood that the number after "DH" correspond to the number of bits of the key.

If we can choose the numbre of bit of the key, of course we choose the lowest one to crack it after.

So we send to alice : 
```text
{"supported": ["DH64"]}
```

Now, we know that the key will be 64bits long.

##### Reminder of Diffie-hellman : 

![img](../../assets/diffie-hellman-algorithm.webp)

The complexity of Diffie-Helman is that we can not guess Alice & Bob private keys. We also can not bruteforce keys because with a 2048 bits key we have 2<sup>2048</sup> possibilities and that is enormous.

Here, we have a 64 bits key, we have 2<sup>64</sup> possibilities which is pretty small.

Using [Alpertron](https://www.alpertron.com.ar/DILOG.HTM) we can enter alice data to find her private key (because it's a small one)

![img](../../assets/export_grade.png)

We see that the alice private key is 
```text
7628428214974869407
```

Alice will get the shared private key by calculating B<sup>Alice key</sup> mod p.

We have all these information !

We now have to calculate this shared secret and we can decode the data using the "Starter 5" function : 

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

shared_secret = pow(5545560548494452803,7628428214974869407,16007670376277647657)
iv = "6a55f3d640455efdbba5fe16007608bb"
ciphertext = "920158159e41a3acf36203e521a2a64114baeb848a186144cf9510e42c0ac380"

print(decrypt_flag(shared_secret, iv, ciphertext))
```
