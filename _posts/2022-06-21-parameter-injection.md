---
title: "CryptoHack - Parameter Injection"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'AES','crypto','Diffie-Hellman','MITM']
titlepage: true
toc: true
toc-own-page: true
---

challenge link : https://cryptohack.org/courses/public-key/parameter_injection/


### Instruction : 

You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at nc socket.cryptohack.org 13371

### Solution : 

We can rewrite Alice's Data and send it to bob.

If we change Alice's public key and set it to '0', Bob will do 0<sup>Bob Private Key</sup> mod p. The result will be always 0 because 0<sup>anything</sup>=0.
We do the same for Alice and Alice will do B<sup>Alice private key</sup> mod p and the result will be 0 too.

After that we know that the shared key is 0 and we can decipher the text thanks to the given function.

Let's automate the process with python : 

```python

from pwn import * # pip install pwntools
import json

r = remote('socket.cryptohack.org', 13371)


alice=r.recvline().decode().split('Intercepted from Alice: ')[1] #We store only json
alice=json.loads(alice)

alice['A']=hex(0) #change Alice result to 0

request = json.dumps(alice).encode()
r.sendline(request)#send it


bob=r.recvline().decode().split('Intercepted from Bob: ')[1]
bob=json.loads(bob)

bob['B']=hex(0) #change bob result to 0

request = json.dumps(bob).encode()
r.sendline(request) #send it

result=r.recvline().decode().split('Intercepted from Alice: ')[1]
result=json.loads(result) #Reading the result



###Starter 5 decrypt.py
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
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


shared_secret = 0 #We know that shared key is 0
iv = result['iv']
ciphertext = result['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))


```