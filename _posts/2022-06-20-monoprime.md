---
title: "CryptoHack - Monoprime"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','modular math','factorization','prime']
titlepage: true
toc: true
toc-own-page: true
---

challenge link : https://cryptohack.org/courses/public-key/monoprime/


### Instructions:

Why is everyone so obsessed with multiplying two primes for RSA. Why not just use one?

output.txt

### Solution :

If he use only one prime then p=q.

[Looking at these discussion](https://crypto.stackexchange.com/questions/5715/phipq-p-1-q-1) we have : 

![picture](../../assets/monoprime.png).

Let's check if n is prime thanks to Fermat's little theorem.

```python
def fermat(nb):
    for i in range(300):
        if pow(getPrime(100),nb-1,nb)!=1:
            return False
    return True

print(fermat(n))

output: True
```

tot(n) is the number of prime number with n. Since n is prime then all numbers in the set are prime to n. We therefore have n-1 prime element with n .
tot(n)=n-1
```text
n=171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591

tot(n)=n-1
```

d=e<sup>-1</sup> mod tot(n)

```python
from Crypto.Util.number import long_to_bytes
n=171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591
tot=n-1
e=65537
ct=161367550346730604451454756189028938964941280347662098798775466019463375610700074840105776873791605070092554650190486030367121011578171525759600774739890458414593857709994072516290998135846956596662071379067305011746842247628316996977338024343628757374524136260758515864509435302781735938531030576289086798942

d=pow(e,-1,tot)

decrypt=pow(ct,d,n)

print(long_to_bytes(decrypt))
```

