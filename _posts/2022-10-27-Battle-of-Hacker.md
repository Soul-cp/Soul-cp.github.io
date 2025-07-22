---
title: "Battle of Hacker 2022 "
date: 2022-10-27
categories: [CTF]
tags: [ Reverse Engineering ]
image: assets/writeups/BOH2022/BOH1.png
---

## 🧩 Challenge Overview

**Challenge Name**: baby flag-checker
**Description** : This simple yet accurate flag-checker program is designed to perform 2 rounds of checking for high precision!

## 🔍 Recon and Static Analysis

I start with the basics thing. When I get the file.

```bash
file flagchecker
strings flagchecker
```

![img](assets/writeups/BOH2022/BOH2.png)

![img](assets/writeups/BOH2022/BOH3.png)


Some interesting strings appear:

```text
[!] Guess a 8-digit secret number to pass the test!
[!] What will you do?
[!] Enter Flag:
[+] Correct Flag!
[-] Wrong Flag!
```
Next, I ran the file and it displayed a logo: Battle of Hackers 2022. There were two options shown. The first option was "Earn an attempt", which allows you to gain extra attempts if you correctly guess the next number. This means that when you choose the second option to check the flag, your chances of getting it right increase because you have more than one attempt.

![img](assets/writeups/BOH2022/BOH4.png)

So here I load the binary into IDA , and after see some functions and analyzing the flow, we find two main functions:

1.Human Verification Logic

2.Flag Check Logic

![img](assets/writeups/BOH2022/BOH5.png)

🚫 Skipping the Number Guess

In sub_131A(), the binary tries to generate an 8-digit number using 

This is sub_12CF

```c
sub_12CF(10000000, 99999999);
 return (unsigned int)(rand() % (a2 + 1 - a1) + a1);
```

This is sub_131A()

```c
unsigned __int64 sub_131A()
{
  unsigned int v1; // [rsp+Ch] [rbp-214h]
  char s[256]; // [rsp+10h] [rbp-210h] BYREF
  char nptr[264]; // [rsp+110h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+218h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v1 = sub_12CF(10000000, 99999999);
  printf("\x1B[1;32m\n[!] Guess a 8-digit secret number to pass the test!");
  printf("\n[!] However, one attempt will be deducted if you lose!");
  puts("\n[!] What will you do?");
  printf("\n1. Continue with the test");
  printf("\n2. Abort");
  printf("\n> ");
  fgets(s, 256, stdin);
  if ( atoi(s) == 1 )
  {
    puts("\x1B[1;32m\n[!] Guess:");
    printf("> ");
    fgets(nptr, 256, stdin);
    if ( v1 == atoi(nptr) )
    {
      puts(a132m_0);
      ++dword_5010;
    }
    else
    {
      printf(a131m, v1);
      --dword_5010;
    }
  }
  else if ( atoi(s) == 2 )
  {
    puts(a131m_0);
  }
  else
  {
    puts("\x1B[1;31m\n[-] Error Encountered! Returning...");
  }
  sub_11C9();
  return v4 - __readfsqword(0x28u);
}
```

But here's the catch the binary doesn't call srand(), so rand() always returns the same number. However, I did not bother figuring it out because I realized it’s just a gate to increment a counter dword_5010.Since I'm  not testing against a remote server, and this guessing logic doesn’t actually validate anything related to the flag, we skip it entirely and analyze the real target Which is the flag checker.

🔐 Flag Validation Logic

In sub_1504, the binary verifies the input by running a custom transformation on each character and comparing it to a hardcoded array byte_2020.

```c
__int64 __fastcall sub_1504(__int64 a1)
{
  int v1; // ebx
  unsigned __int8 v3; // [rsp+17h] [rbp-239h]
  int i; // [rsp+18h] [rbp-238h]
  int v5; // [rsp+1Ch] [rbp-234h]
  char s[256]; // [rsp+30h] [rbp-220h] BYREF
  char nptr[264]; // [rsp+130h] [rbp-120h] BYREF
  unsigned __int64 v9; // [rsp+238h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  v3 = 1;
  for ( i = 0; i < 46; ++i )
  {
    v5 = *(char *)(i + a1) ^ 0x2A;
    if ( i > 22 )
      s[i - 1] = v5 ^ (2 * v5);
    else
      s[i - 1] = (8 * v5) >> 2;
    sprintf(s, "%d", s[i - 1]);
    sprintf(nptr, "%d", byte_2020[i]);
    v1 = atoi(s);
    if ( v1 != atoi(nptr) )
      return 0;
  }
  return v3;
}
```

![img](assets/writeups/BOH2022/BOH6.png)

This function validates a flag. It takes in a pointer to the user input and checks each of the first 46 characters by performing XOR and arithmetic transformations, then compares the result to a predefined byte array (byte_2020). If all 46 transformed bytes match, the function returns 1; indicate true otherwise, it returns 0 indicate false.Next each character is XOR’d with 0x2A, transformed, and compared to a hardcoded table. Now I need to dump byte_2020 from .rodata because this array is the hardcoded target that the transformed flag must match.

![img](assets/writeups/BOH2022/BOH7.png)

After get the byte_2020 , then wrote a brute-force script to reverse the transformation character by character.

```python
byte_2020 = [
    0xD6, 0xF4, 0xFE, 0xD0, 0xCA, 0xC4, 0x30, 0x30, 0xA2,
    0xB8, 0x9E, 0xB0, 0xA6, 0x90, 0x96, 0x90, 0xA6, 0xB0, 0x9E,
    0xB8, 0xEA, 0x90, 0x3C, 0xDB, 0xC3, 0xE7, 0x22, 0xE8, 0xD2,
    0x21, 0x9F, 0xC5, 0x21, 0x9F, 0xE4, 0xD1, 0xE8, 0xF5, 0xD8,
    0xDD, 0xD8, 0xF5, 0xE8, 0xD1, 0xE4, 0xF9
]

flag = ""

for i in range(len(byte_2020)):
    expected = byte_2020[i]
    found = False
    for c in range(0x20, 0x7f):  
        v5 = c ^ 0x2A
        if i > 22:
            transformed = v5 ^ (2 * v5)
        else:
            transformed = (8 * v5) >> 2
        if transformed == expected:
            flag += chr(c)
            found = True
            break
    if not found:
        flag += "?" 

print("Flag : ", flag)
```
![img](assets/writeups/BOH2022/BOH8.png)

And here is the flag : APUBOH22{verybabyrev_b4ckw4rd5_i5_verybabyrev}

I ran again the flagchecker file to confirm my flag and it is correct

![img](assets/writeups/BOH2022/BOH9.png)


