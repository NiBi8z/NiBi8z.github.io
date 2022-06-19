---
title: "CryptoHack - Inferius Prime"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','modular math','factorization']
titlepage: true
toc: true
toc-own-page: true
---

### Instructions:

Here is my super-strong RSA implementation, because it's 1600 bits strong it should be unbreakable... at least I think so!

inferius.py

output.txt

Inferius.py : 

```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

e = 3

# n will be 8 * (100 + 100) = 1600 bits strong which is pretty good
while True:
    p = getPrime(100)
    q = getPrime(100)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    if d != -1 and GCD(e, phi) == 1:
        break

n = p * q

flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag
```

output.txt

```text
n = 742449129124467073921545687640895127535705902454369756401331
e = 3
ct = 39207274348578481322317340648475596807303160111338236677373
```

### Solution


We notice that p and q are generated with getPrime() so we cannot guess them. 

Using [this powerful website](https://www.alpertron.com.ar/ECM.HTM) we can try to factor n. If we succeed we can find tot(n) and therefore find d.


![showing result](../../assets/inferius.png)

Perfect ! We have p and q and the website also computed Euler's totient (p-1*q-1) for us.

We have tot(n) and e. We are able to compute d which is e<sup>-1</sup> mod tot(n) and then find the flag.

Doing it with python :
```python
from Crypto.Util.number import long_to_bytes
n=742449129124467073921545687640895127535705902454369756401331
e=3
tot=742449129124467073921545687639156049064283454870081476956200 #(p-1)*(q-1)
ct=39207274348578481322317340648475596807303160111338236677373

d=pow(e,-1,tot) # inverse of e mod n

decipher=pow(ct,d,n)

ans=long_to_bytes(decipher)
print(ans)
```
