---
title: "CryptoHack - Round Keys"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'AES','crypto']
titlepage: true
toc: true
toc-own-page: true
---

Challenge link : https://cryptohack.org/courses/symmetric/aes3/

## Instructions :

You have to complete the add_round_key function, then use the matrix2bytes function to get your next flag.


Here is the given code : 

```python


state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]


def add_round_key(s, k):
    ????

```

## Solution
So, we have to complete the add_round_key fonction. All we have to do is xor state with round_key one per one.

* xor(state[0][0], round_key[0][0])
* xor(state[1][1], round_key[1][1])

And add results to a 4*4 matrix.

Afterward, we convert our matrix into bytes to get the flag.


python function to xor state and key one per one :

```python
def add_round_key(s, k):
    final=[]
    for i in range(len(s)):
        tmp=[]
        for j in range(len(s)):
            tmp.append(xor(s[i][j],k[i][j]))
        final.append(tmp)            
    return final
```

By running this function with state and round_key as parameters we have : 

```python
[[99, 114, 121, 112], [116, 111, 123, 114], [48, 117, 110, 100], [107, 51, 121, 125]]
```

Now, let's convert all these characters to string with   [matrix2bytes](../../posts/CRYPTOHACK-structure-of-aes/)
function.

```python
def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    res=b''
    for i in matrix:
        for j in i:
            res+=chr(j).encode()
    return res
```

Perfect, we now have the flag.

