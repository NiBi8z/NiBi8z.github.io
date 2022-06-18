---
title: "CryptoHack - Structure of AES"
author: NiBi
lang: "en"
categories : ['CryptoHack']
tags : ['Challenge', 'AES','crypto']
titlepage: true
toc: true
toc-own-page: true
---

challenge link : https://cryptohack.org/courses/symmetric/aes2/


## Instructions : 


Included is a bytes2matrix function for converting our initial plaintext block into a state matrix. Write a matrix2bytes function to turn that matrix back into bytes, and submit the resulting plaintext as the flag.


Here is the given code : 

```python

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    ????


matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

print(matrix2bytes(matrix))
```

## Solution 

The bytes2matrix function make block of four bytes with our text and add the ascii value of each character into a 4*4 matrix.

We have to take each integer and convert them to characters using ascii tables 

Let's do it.

```python
def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    res=b''
    for i in matrix:
        for j in i:
            res+=chr(j).encode()
    return res
```

Done, we now have the flag.