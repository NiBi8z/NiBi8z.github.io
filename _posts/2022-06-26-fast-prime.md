---
title: "CryptoHack - Fast Primes"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','ROCA']
titlepage: true
toc: true
toc-own-page: true
---

#### Instructions : 

I need to produce millions of RSA keys quickly and the standard way just doesn't cut it. Here's yet another fast way to generate primes which has actually resisted years of review.

Challenge files:
  - fast_primes.py
  - key.pem
  - ciphertext.txt


fast_primes.py
```python

#!/usr/bin/env python3

import math
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, inverse
from gmpy2 import is_prime


FLAG = b"crypto{????????????}"

primes = []


def sieve(maximum=10000):
    # In general Sieve of Sundaram, produces primes smaller
    # than (2*x + 2) for a number given number x. Since
    # we want primes smaller than maximum, we reduce maximum to half
    # This array is used to separate numbers of the form
    # i+j+2ij from others where 1 <= i <= j
    marked = [False]*(int(maximum/2)+1)

    # Main logic of Sundaram. Mark all numbers which
    # do not generate prime number by doing 2*i+1
    for i in range(1, int((math.sqrt(maximum)-1)/2)+1):
        for j in range(((i*(i+1)) << 1), (int(maximum/2)+1), (2*i+1)):
            marked[j] = True

    # Since 2 is a prime number
    primes.append(2)

    # Print other primes. Remaining primes are of the
    # form 2*i + 1 such that marked[i] is false.
    for i in range(1, int(maximum/2)):
        if (marked[i] == False):
            primes.append(2*i + 1)


def get_primorial(n):
    result = 1
    for i in range(n):
        result = result * primes[i]
    return result


def get_fast_prime():
    M = get_primorial(40)
    while True:
        k = random.randint(2**28, 2**29-1)
        a = random.randint(2**20, 2**62-1)
        p = k * M + pow(e, a, M)

        if is_prime(p):
            return p


sieve()

e = 0x10001
m = bytes_to_long(FLAG)
p = get_fast_prime()
q = get_fast_prime()
n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d))
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(FLAG)

assert cipher.decrypt(ciphertext) == FLAG

exported = key.publickey().export_key()
with open("key.pem", 'wb') as f:
    f.write(exported)

with open('ciphertext.txt', 'w') as f:
    f.write(ciphertext.hex())
```

#### Solution : 

We find that M is a factor of P. M is "get_primorial(40)" which is always the same number. Both p and q will share a same factor : M. I searched a lot on internet and i have found the ["roca" attack](https://en.wikipedia.org/wiki/ROCA_vulnerability).

Using [RSACtfTool](https://github.com/Ganapati/RsaCtfTool) we break the key easily because n is simply broken... We do not even need the roca attack, using factordb we get p et q. With p and q we can have phi and the deciphered text.

```shell
┌──(kali㉿kali)-[~/RsaCtfTool]
└─$ ./RsaCtfTool.py --publickey ../key --uncipher 1917684880911867693650685352418976984109248146699653008498254042568729095851205293666079588834526955087298417903949404082481371089615961547716198943362344
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key ../key.
[*] Performing mersenne_primes attack on ../key.
 24%|███████████████████████████████████████████▌                                                                                                                                             | 12/51 [00:00<00:00, 284359.59it/s]
[*] Performing smallq attack on ../key.
[*] Performing system_primes_gcd attack on ../key.
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 7007/7007 [00:00<00:00, 1006489.32it/s]
[*] Performing nonRSA attack on ../key.
[*] Performing factordb attack on ../key.
[*] Attack success with factordb method !

Results for ../key:

Unciphered data :
HEX : 0xdb399aa127be4ae31fd97c20254718b33cc2f38727abdddeabc924cd254153291d9eb63729823bca6ff327f1714ec9342fdd0cf37a801388793e3b23d4fb28
INT (big endian) : 44850569214881713558668609493518231482054817376499457246532789308666571922968123835475628673877508976972939359835932184080315801143996699673272167758632
INT (little endian) : 8384729834905722449278043599998413844644268058872587209088863552570247949756796080837921964555071830136422457171642997288486478561051877581061327829467
STR : b"\xdb9\x9a\xd9| %G\x18\xb3<\xc2\xf39$\xcd%AS)\x1d\x9e\xb67)\x82;\xcao\xf3'\xf1qN\xc94/\xdd\x0c\xf3z\x88y>;#\xd4\xfb("
HEX : 0x637279...537306e31347d
INT (big endian) : 567742950117184...32502550066638173309
INT (little endian) : 714787567...60602219549596153741406819
utf-8 : [FLAG]
utf-16 : 牣灹ㅮ紴
STR : [FLAG]
HEX : 0x00db399aa127be4ae31fd97...823bca6ff327f1714ec9342fdd0cf37a801388793e3b23d4fb28
INT (big endian) : 44850569214881713558...46532789308666571922968123835475628673877508976972939359835932184080315801143996699673272167758632
INT (little endian) : 2146490837735864947...593944228932623071382325526749069457983475137739796694508022926098388514924149035940607305852538511629280660751699924343552
STR : b"\x00\<\\xf3\x87'\xab\xdd\xde\xab\xc9$\xcd%AS)\x1d\x9e\xb67)\x82;\xcao\xf3'\xf1qN\xc94/\xdd\x0c\xf3z\x80\x13\x#\xd4\xfb("
                                                        
```