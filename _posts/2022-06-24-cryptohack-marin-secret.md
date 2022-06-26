---
title: "CryptoHack - Marin's Secrets"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','modular math','factorization']
titlepage: true
toc: true
toc-own-page: true
---

#### Instructions : 
I've found a super fast way to generate primes from my secret list.

Challenge files:
  - marin.py
  - output.txt

marin.py : 

```python
#!/usr/bin/env python3

import random
from Crypto.Util.number import bytes_to_long, inverse
from secret import secrets, flag


def get_prime(secret):
    prime = 1
    for _ in range(secret):
        prime = prime << 1
    return prime - 1


secrets = random.shuffle(secrets)

m = bytes_to_long(flag)
p = get_prime(secrets[0])
q = get_prime(secrets[1])
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

```

### Solution : 


Here, we see that we can not guess these number because we do not know the values of the secret list.

We can not guess p and q and we can not have any information about the key. 

Using [factordb](http://factordb.com/) i searched for n and it was known !

![img](../../assets/factordb_marin.png)

Luckily, we now have the factorized version of n. Because we have p and q we also have tot(n) by doing (p-1)*(q-1). Then we calculate d because d=e<sup>-1</sup> mod tot(n).

After what we can decipher text ! 
See more details about RSA [here](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption)

With python we get : 

```python
from Crypto.Util.number import long_to_bytes

q=pow(2,2203-1)
p=pow(2,2281-1)

tot=(p-1)*(q-1)
cipher=40028046308893...981555179129287164971002033759724456
e=65537
n=658416274830184544125024117184808822828370900198489249243399165125219244753790779764466236965135793576516193213175061401...02259605109600363098950091998891375812839523613295667253813978434879172781217285652895469194181218343078754501694746598738215243769747956572555989594598180639098344891175879455994652382137038240166358066403475457

d=pow(e,-1,tot)


decrypt=pow(cipher,d,n)

print(long_to_bytes(decrypt))
```