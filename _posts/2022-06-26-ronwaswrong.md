---
title: "CryptoHack - Ron was Wrong, Whit is Right"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','factorization']
titlepage: true
toc: true
toc-own-page: true
---

#### Instructions : 

Here's a bunch of RSA public keys I gathered from people on the net together with messages that they sent.

As excerpt.py shows, everyone was using PKCS#1 OAEP to encrypt their own messages. It shouldn't be possible to decrypt them, but perhaps there are issues with some of the keys?

Challenge files:
  - excerpt.py
  - keys_and_messages.zip

Resources:
  - The recent difficulties with RSA


#### Solution : 

By reading the given article we discover the investigation of 6 researchers. In fact, theses researchers collected millions of RSA key on internet.
They calculated the Greatest common divisor of all key. In fact, if two keys are prime to each other the GCD is 1. If the GCD is not 1, it's mean that the keys share one factor !

Because having tso huge primes factor is hard, a lot of peoples reuse known prime number.

We can not factorize all the key because they are to big, but if we know that two key share one factor, we can deduce p and q.

Let's have a look with a little exemple : 

Imagine that we have a public key that is 35 and another one that is 77.

If we imagine that 35 and 77 are too big to be factorized, we can try calculate the gcd of these numbers. 

The GCD of 35 and 77 is equal to 7. That's mean that 35 = 7\*x and 77 = 7\*x.

We can find the x easily because 35/7=x and 77/7=x.

We have respectively 5 and 11. 

Now, we know that 35 = 7 * 5 and 77 = 7*11 because these two numbers are not prime among themselves.

In the challenge, 50 public keys are provided. If we find two numbers whose GCD is different from 1, we can find p and q exactly as we did before. Then we can compute phi which is (p-1)*(q-1) and calculate d two decrypt the message.

Let's do it with python : 

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from math import gcd

n=[]
c=[]
e=[]

for i in range(1, 51):
    key = RSA.importKey(open(f"{i}.pem", 'r').read())
    cipher = open(f"{i}.ciphertext", 'r').read()
    n.append(key.n) # we load all keys
    c.append(cipher)
    e.append(key.e)

N = 0
for i in range(len(n)):
    for j in range(i,len(n)):
        tmp = gcd(n[i], n[j])
        if tmp != 1 and n[i]!=n[j]: # if a GCD if different from 1, we stock it.
            N =tmp
            index = i

e = e[index] 
factor_1 = N #First factor is the GCD of numbers who are sharing a common factor. (p)
factor_2 = n[index]//N #We find the second factor (q)
phi = (factor_1-1)*(factor_2-1) #we calculate phi
d = pow(e,-1, phi) #Then d

key = RSA.construct((n[index], e, d)) #We decipher the text
cipher = PKCS1_OAEP.new(key)
decrypt = cipher.decrypt(bytes.fromhex(c[index]))
```
