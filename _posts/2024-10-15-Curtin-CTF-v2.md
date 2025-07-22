---
title: "RK 800 2024 -Writeup"
date: 2024-10-15
categories: [CTF, Writeup]
tags: [Osint,Reverse Engineering]
image: assets/writeups/Curtin/C1.png
---

Here, I’m post one OSINT challenge and  the Reverse Engineering challenges only.

### Challenge name : Colliding Image Pair ###
### category : Osint ###

![img](/assets/writeups/Curtin/C2.png)

First we were given a link to github . open the link and we found the author github . It a post about some picture and a comment . All of this are actually a hint for us how to solve the question . the image hash is a big clue we will use later . 

![img](/assets/writeups/Curtin/C3.png)
![img](/assets/writeups/Curtin/C4.png)
![img](/assets/writeups/Curtin/C5.png)

Next up I went to search more about the author Using intel technique tool to search to search I get a lot of social media of the author but it seems not useful . Untill I found an interesting picture where it same as a github picture on website flickr. 

![img](/assets/writeups/Curtin/C6.png)
![img](/assets/writeups/Curtin/C7.png)

When click the picture there is one comment that the author commented it  . When click , it redirect to another cloud web where there is a file zip. So I just directly download the zip file first.

![img](/assets/writeups/Curtin/C8.png)
![img](/assets/writeups/Curtin/C9.png)

After unzipping the file , I got a lot of image but all of it are same picture with different name . At first  I was stuck what should I do with this after rechecking my step again . Then I remeber that on github there is a commented md5 checksum from the author .

![img](/assets/writeups/Curtin/C10.png)

Using the earlier clue I got I use command md5sum to check the hash and grep for specify same as the commented on github without wasting time use * to check all the image and grep I want

![img](/assets/writeups/Curtin/C11.png)

Boom !!! I found the image that contain same md5 hash . At first I still Clueless what to do with this name of the image untill I found out that the github link use gist on in front of the url So this might be a gist github . So add the file name on the url and we got the flag .

![img](/assets/writeups/Curtin/C12.png)

# Category : Reverse Engineering
## Challenge Name : broken

### Description ###
Would you really rather have my payload execute on yours?

Flag format: flag{...}

First, we run the classic file inspection command

![img](/assets/writeups/Curtin/C14.png)

This tells us what kind of binary we’re dealing with.
Then we follow up with strings to check for any embedded plain-text clues:

![img](/assets/writeups/Curtin/C13.png)

After running the strings command and inspecting the output using `tail` and `less` , I wasn’t able to find anything useful. So, I decided to search more directly using grep. Since the challenge description mentioned that the flag format was flag{...}, I searched for the string ` flag{ ` and that’s how I found the flag embedded in the binary.

![img](/assets/writeups/Curtin/C15.png)

# Category : Reverse Engineering
## Challenge Name : just_Ring

### Description ###
as it sounds

As usual first I will use file command . 

![img](/assets/writeups/Curtin/C16.png)

Next I used `strings` to check printable ASCII so here I found the clue that when you running the program , after you enter an input it will give us encoded_secret.txt . So I 
straight away run the file and enter red. it give us encoded_secret.txt . using command `cat` to open the file its look like a base64 , decode it and you get the flag . 

![img](/assets/writeups/Curtin/C17.png)

![img](/assets/writeups/Curtin/C18.png)

# Category : Reverse Engineering
## Challenge Name : PinValidator

### Description ###
Unlock the app with the PIN to get the flag.

Given an apk file . using tools `jadx` to decompile the file . find the main function . The pin was display there 

![img](/assets/writeups/Curtin/C19.png)

So now I know the pin was 7331 . Next I use my phone to enter the pin and I get the flag . 

![img](/assets/writeups/Curtin/C20.png)

# Category : Reverse Engineering
## Challenge Name : sl_eep

### Description ###

SL (Steam Locomotive) runs across your terminal when you type "sl" as you meant to type "ls". It's just a joke, and not useful at all but you could fish out a flag I planted somewhere in there.

First I analyzing the file using command  `file` to check the type and `strings` but nothing much info  I get from it. Tyhe ext step I load the file in ghidra to disassemble it. While analyzing the functions, one specific function caught my eye.Which is `checker` function . 

![img](/assets/writeups/Curtin/C21.png)

```text
undefined4 checker(char *param_1)

{
  char cVar1;
  int iVar2;
  size_t sVar3;
  long lVar4;
  undefined4 uVar5;
  uint auStack_13c [15];
  int aiStack_100 [16];
  undefined8 uStack_c0;
  uint local_b8 [8];
  uint local_98 [8];
  uint local_78 [22];
  
  local_78[0] = 0x50a;
  local_78[1] = 0x543;
  local_78[2] = 0x54a;
  local_78[3] = 0x54c;
  local_78[4] = 0x55f;
  local_78[5] = 0x558;
  local_78[6] = 0x55a;
  local_78[7] = 0x502;
  local_78[8] = 0x55f;
  local_78[9] = 0x541;
  local_78[10] = 0x555;
  local_78[0xb] = 0x558;
  local_78[0xc] = 0x55a;
  local_78[0xd] = 0x508;
  local_78[0xe] = 0x556;
  local_78[0xf] = 0x557;
  local_78[0x10] = 0x542;
  local_78[0x11] = 0x554;
  local_78[0x12] = 0x50a;
  local_78[0x13] = 0x54e;
  local_98[0] = 0x54;
  local_98[1] = 0x42;
  local_98[2] = 0x45;
  local_98[3] = 0x43;
  local_98[4] = 0x5e;
  local_98[5] = 0x59;
  local_b8[0] = 0x2b;
  local_b8[1] = 0x2d;
  local_b8[2] = 0x3e;
  local_b8[3] = 0x36;
  local_b8[4] = 0x31;
  uStack_c0 = 0x103427;
  sVar3 = strlen(param_1);
  uVar5 = 0;
  if ((((sVar3 == 0x30) && (cVar1 = param_1[0x19], cVar1 == param_1[0x20])) &&
      (cVar1 == param_1[0x26])) && (param_1[0x26] == param_1[0x29])) {
    if ((param_1[0x2b] == param_1[0x29]) && (cVar1 == '_')) {
      lVar4 = 5;
      uVar5 = 1;
      do {
        if (((int)param_1[lVar4] ^ 0x53bU) != local_98[lVar4 + 3]) {
          uVar5 = 0;
        }
        lVar4 = lVar4 + 1;
      } while (lVar4 != 0x19);
      lVar4 = 0x1a;
      do {
        if ((int)(char)(param_1[lVar4] ^ 0x37) != aiStack_100[lVar4]) {
          uStack_c0 = 0x1034b9;
          printf("failed second check    %c\n",(ulong)(uint)(int)param_1[lVar4]);
          uVar5 = 0;
        }
        lVar4 = lVar4 + 1;
      } while (lVar4 != 0x20);
      lVar4 = 0x21;
      do {
        if (((int)param_1[lVar4] ^ 0x5fU) != auStack_13c[lVar4]) {
          uVar5 = 0;
        }
        lVar4 = lVar4 + 1;
      } while (lVar4 != 0x26);
      if (param_1[0x27] != 'a') {
        uVar5 = 0;
      }
      if (param_1[0x28] != 't') {
        uVar5 = 0;
      }
      uStack_c0 = 0x10352e;
      iVar2 = strncmp(param_1 + 0x11,"3/4}",4);
      if (iVar2 == 0) {
        uStack_c0 = 0x10354a;
        iVar2 = strncmp(param_1,"flag{",5);
        if ((iVar2 == 0) && (param_1[0x2a] == '9')) {
          uVar5 = 0;
        }
      }
    }
    else {
      uVar5 = 0;
    }
  }
  return uVar5;
}
```

The checker function implements a series of checks on the input string.

The function employs three distinct loops, each performing XOR operations on different segments of the param_1 string. The results are then compared against values stored in pre-initialized arrays (local_78, local_98, local_b8). Based on common patterns in decompiled CTF binaries, array indexing for stack variables is often relative to the loop's starting offset.

1.First Loop (Indices 5-24):

This loop targets characters from param_1[5] up to param_1[24]. The transformation is param_1[i] = chr(local_78[i - 5] ^ 0x53b) for i ranging from 5 to 24.
local_78 values: [0x50a, 0x543, 0x54a, 0x54c, 0x55f, 0x558, 0x55a, 0x502, 0x55f, 0x541, 0x555, 0x558, 0x55a, 0x508, 0x556, 0x557, 0x542, 0x554, 0x50a, 0x54e].

2.Second Loop (Indices 26-31):

This loop affects characters from param_1[26] to param_1[31]. The transformation applied is param_1[i] = chr(local_98[i - 26] ^ 0x37) for i from 26 to 31.
local_98 values: [0x54, 0x42, 0x45, 0x43, 0x5e, 0x59].

3.Third Loop (Indices 33-37):

This loop processes characters from param_1[33] to param_1[37]. The transformation is param_1[i] = chr(local_b8[i - 33] ^ 0x5f) for i from 33 to 37.
local_b8 values: [0x2b, 0x2d, 0x3e, 0x36, 0x31].

With all the information we get we can write a python script to reconstruct the flag.

```python
flag_bytes = bytearray(48)

flag_bytes[0:5] = b"flag{"

_char = ord('_')
flag_bytes[25] = _char
flag_bytes[32] = _char
flag_bytes[38] = _char
flag_bytes[41] = _char
flag_bytes[43] = _char

# Part 1 (index 5 to 24)
enc1 = [0x50a, 0x543, 0x54a, 0x54c, 0x55f, 0x558, 0x55a, 0x502, 0x55f, 0x541, 0x555, 0x558, 0x55a, 0x508, 0x556, 0x557, 0x542, 0x554, 0x50a, 0x54e]
for i in range(len(enc1)):
    flag_bytes[i + 5] = enc1[i] ^ 0x53b

# Part 2 (index 26 to 31)
enc2 = [0x54, 0x42, 0x45, 0x43, 0x5e, 0x59]
for i in range(len(enc2)):
    flag_bytes[i + 26] = enc2[i] ^ 0x37

# Part 3 (index 33 to 37)
enc3 = [0x2b, 0x2d, 0x3e, 0x36, 0x31]
for i in range(len(enc3)):
    flag_bytes[i + 33] = enc3[i] ^ 0x5f

flag_bytes[39] = ord('a')
flag_bytes[40] = ord('t')
flag_bytes[42] = ord('9') # This char passes because the check for '9' is bypassed
flag_bytes[44:48] = b"3/4}" # This '3/4}' is placed at the end, not at index 17

final_flag = flag_bytes.decode('ascii')
print(final_flag)
```
![img](/assets/writeups/Curtin/C22.png)

# Category : Reverse Engineering
## Challenge Name : Wrot

### Description ###
It might help to identify the algorithm here :P

ACME. Inc directed its cryptography team to encode the flag in a way that no bits are lost. A flag was encrypted and store in the comment within the file - can you help the team find the lost flag?

The challenge presented an encrypted flag, enc, which was encoded using a custom Python function named enc_shift. This function implements a circular bit shift, either to the left or right, for each character of the original flag. The task was to reverse this encryption process to reveal the "lost flag".

```python
def enc_shift(n: int, bits: int, shift: int, direction: str = 'left') -> int:
    bit_len = bits
    
    if direction == 'left':
        return ((n << shift) | (n >> (bit_len - shift))) & ((1 << bit_len) - 1)
    elif direction == 'right':
        return ((n >> shift) | (n << (bit_len - shift))) & ((1 << bit_len) - 1)
    else:
        raise ValueError("Something's not right\n")



flag = 'LOST_FLAG'
shifted = []
bits = 8

for i in range(len(flag)):
    if (i%2 == 0):
        shifted.append(enc_shift(ord(flag[i]), bits, 2, 'left'))
    else:
        shifted.append(enc_shift(ord(flag[i]), bits, 2, 'right'))


print(shifted)

# enc = [153, 27, 133, 217, 237, 146, 49, 14, 49, 210, 9, 153, 153, 205, 145, 157, 212, 221, 193, 157, 9, 82, 228, 21, 13, 215, 185, 219, 125, 152, 165, 29, 205, 215, 177, 12, 212, 205, 245]
```
The core of the encryption lies in the `enc_shift` function.
1. Each character of the flag was converted to its ASCII integer representation.

2. For characters at even indices (i % 2 == 0), a left circular shift by 2 bits was applied.

3. For characters at odd indices (i % 2 != 0), a right circular shift by 2 bits was applied.

4. All operations were performed within an 8-bit length (bits = 8), meaning the values wrap around after 255 (0xFF).

5. The resulting encrypted flag was provided as a list of integers:
enc = [153, 27, 133, 217, 237, 146, 49, 14, 49, 210, 9, 153, 153, 205, 145, 157, 212, 221, 193, 157, 9, 82, 228, 21, 13, 215, 185, 219, 125, 152, 165, 29, 205, 215, 177, 12, 212, 205, 245]

Next write a python script to decrypt the enc list and reveal the  flag.

```python
def dec_shift(n: int, bits: int, shift: int, direction: str = 'left') -> int:
    bit_len = bits
    
    if direction == 'left': # If we are reversing a right shift
        return ((n << shift) | (n >> (bit_len - shift))) & ((1 << bit_len) - 1)
    elif direction == 'right': # If we are reversing a left shift
        return ((n >> shift) | (n << (bit_len - shift))) & ((1 << bit_len) - 1)
    else:
        raise ValueError("Invalid direction for decryption\n")

enc = [153, 27, 133, 217, 237, 146, 49, 14, 49, 210, 9, 153, 153, 205, 145, 157, 212, 221, 193, 157, 9, 82, 228, 21, 13, 215, 185, 219, 125, 152, 165, 29, 205, 215, 177, 12, 212, 205, 245]
bits = 8
shift = 2
decrypted_chars = []

for i in range(len(enc)):
    if (i % 2 == 0): # Originally left-shifted, so decrypt with right shift
        decrypted_chars.append(dec_shift(enc[i], bits, shift, 'right'))
    else: # Originally right-shifted, so decrypt with left shift
        decrypted_chars.append(dec_shift(enc[i], bits, shift, 'left'))

flag = ""
for char_code in decrypted_chars:
    flag += chr(char_code)

print(flag)
```

flag{JL8LKBff7dv5wpvBI9TC_no_bits_l057}












