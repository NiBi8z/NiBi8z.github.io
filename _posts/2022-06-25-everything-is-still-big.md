---
title: "CryptoHack - Everything is still big"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'RSA','crypto','math','sagemath','boneh-durfee']
titlepage: true
toc: true
toc-own-page: true
---


#### Instructions : 

Okay so I got a bit carefree with my last script, but this time I've protected myself while keeping everything really big. Nothing will stop me and my supercomputer now!

Challenge files:
  - source.py
  - output.txt

Resources:
  - Twenty Years of Attacks on the RSA Cryptosystem

#### Solution : 

I read the given pdf and the fourth page caught my attention. The chapter "Low private exponent" talks about the risk of having a huge e. If e is big, d can be small mod n. Thanks to "boneh-durfee" attack we can retrieve d if it is small.

I've found [this repo](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage) on github.

Let's use sagemath and try to find d.

d will be found if d<N<sup>0.292</sup>

```shell
┌──(kali㉿kali)-[~]
└─$ sage rsa_attack.sage
=== checking values ===
* delta: 0.180000000000000
* delta < 0.292 True
* size of e: 2045
* size of N: 2046
* m: 4 , t: 2
=== running algorithm ===
* removing unhelpful vector 0
6 / 18  vectors are not helpful
det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)
00 X 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ~
01 X X 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
02 0 0 X 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ~
03 0 0 X X 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
04 0 0 X X X 0 0 0 0 0 0 0 0 0 0 0 0 0 
05 0 0 0 0 0 X 0 0 0 0 0 0 0 0 0 0 0 0 ~
06 0 0 0 0 0 X X 0 0 0 0 0 0 0 0 0 0 0 ~
07 0 0 0 0 0 X X X 0 0 0 0 0 0 0 0 0 0 
08 0 0 0 0 0 X X X X 0 0 0 0 0 0 0 0 0 
09 0 0 0 0 0 0 0 0 0 X 0 0 0 0 0 0 0 0 ~
10 0 0 0 0 0 0 0 0 0 X X 0 0 0 0 0 0 0 ~
11 0 0 0 0 0 0 0 0 0 X X X 0 0 0 0 0 0 
12 0 0 0 0 0 0 0 0 0 X X X X 0 0 0 0 0 
13 0 0 0 0 0 0 0 0 0 X X X X X 0 0 0 0 
14 X X 0 X X 0 0 0 0 0 0 0 0 0 X 0 0 0 
15 0 0 X X X 0 X X X 0 0 0 0 0 0 X 0 0 
16 0 0 0 0 0 X X X X 0 X X X X 0 0 X 0 
17 0 0 X X X 0 X X X 0 0 X X X 0 X X X 
optimizing basis of the lattice via LLL, this can take a long time
LLL is done!
looking for independent vectors in the lattice
found them, using vectors 0 and 1
=== solution found ===
private key found: 1178047123867005117803610...829687625029129242589458595768537819428280893758899509
=== 0.5668575763702393 seconds ===
```

Voila, we have d !

Now, we can decrypt the message with python

```python
from Cryptodome.PublicKey import RSA
from Crypto.Util.number import long_to_bytes


message=int('0x503d5dd3bf3d76918b868c0789c81b4a384184ddadef81142eabdcb78656632e54c9cb22ac2c41178607aa41adebdf89cd24ec1876365994f54f2b8fc492636b59382eb5094c46b5818cf8d9b42aed7e8051d7ca1537202d20ef945876e94f502e048ad71c7ad89200341f8071dc73c2cc1c7688494cad0110fca4854ee6a1ba999005a650062a5d55063693e8b018b08c4591946a3fc961dae2ba0c046f0848fbe5206d56767aae8812d55ee9decc1587cf5905887846cd3ecc6fc069e40d36b29ee48229c0c79eceab9a95b11d15421b8585a2576a63b9f09c56a4ca1729680410da237ac5b05850604e2af1f4ede9cf3928cbb3193a159e64482928b585ac',16)

n=1291644713745307443546968884262229450843875129917053552876321008644191767256511128834777932397603711984969074559709840520428084122370851250973658415386...1841090057259646226194981126956532671953413964735202375312868160112350373415379463907794108927768398835451176758241138626065075767232526577752765330761267711167537861048249
d=1178047123...5029129242589458595768537819428280893758899509
decrypt=pow(message,d,n)


print(long_to_bytes(decrypt))
```

#### Another solution : 

Using [factordb](http://factordb.com/) we discover that n is known and we have p and q. So we can deduce d.