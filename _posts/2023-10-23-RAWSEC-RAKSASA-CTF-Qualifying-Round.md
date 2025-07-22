---
title: "RAWSEC RAKSASA CTF 2023 Qualifying Round"
date: 2023-10-23 
categories: [CTF]
tags: [Reverse Engineering]
image: assets/writeups/Rawsec/Rawsec.png
---

## Challenge: crackme if you can  
**Category:** Reverse Engineering  
**Event:** RAWSEC RAKSASA CTF 2023  
**Date:** October 23, 2023

---

### Initial Analysis

We were given a file named `crackme.exe`.  
First, I ran the `file` command to check the file type

![img](assets/writeups/Rawsec/Screenshot 2025-05-01 200829.png)

The result shows that the binary is a 32-bit PE executable and is packed using UPX.
To unpack it use command `upx -d crackme.exe` and check `file` again to confirm it . The file already decompress
or not

![img](assets/writeups/Rawsec/UPX.png)

After successful unpacking, I proceeded with static analysis using `Ghidra`. On the main function I already see the logic that might be the clue. After reading this code and understand it, this is a system of nonlinear equations where only one value (local_14) was known, and the rest had to be derived through substitution and algebra.

![img](assets/writeups/Rawsec/Ghidra.png)

Only (local_14) were given so we already now the (1st number) . 

![img](assets/writeups/Rawsec/local14.png)

Next do the equation 

```text
local_14 + (local_20 * 3) == 0x467c
→ 1010 + (local_20 * 3) = 18044
→ local_20 * 3 = 17034
→ local_20 = 5678
```
So we found the (4th number) local_20 = 5678

```text
local_1c * 0xc0d3 + local_20 == 0x3cbbd6c
→ local_1c * 49363 + 5678 = 63683948
→ local_1c * 49363 = 63683948 - 5678 = 63678270
→ local_1c = 1290
```
local_1c = 1290 (3rd number)

```text
local_1c * local_18 * 3 == 0x4ef3ae
→ 1290 * local_18 * 3 = 5174190
→ local_18 * 3= 5174190 / 1290
→ local_18 = 4011/3
→ local_18 = 1337

```
local_18 = 133 (2nd number)

**Final Input**

We already had:

| Variable   | Value | Position in Flag |
|------------|--------|------------------|
| `local_14` | 1010  | 1st              |
| `local_18` | 1337  | 2nd              |
| `local_1c` | 1290  | 3rd              |
| `local_20` | 5678  | 4th              |

Now let's try submit it on crackme.exe

![img](assets/writeups/Rawsec/FinalOutput.png)

So , The flag is `WSCTF2021{1010-1337-1290-5678}`

## Challenge: Showflag.exe
**Category:** Reverse Engineering  
**Event:** RAWSEC RAKSASA CTF 2023  
**Date:** October 23, 2023

### Initial Analysis

The first thing i do is check the file type using command `file` showing the result is ``PE32+`` executable and .NET Assembly.

![img](assets/writeups/Rawsec/1.png)

So it's a GUI running on windows and .NET Assembly.Next use dnspy to dissamble it . Upon Analyze it I found that there is 6 flag in total . So the exe file when you run it show the flag. But here it only show 5 flag and missing 1 so here I found out there must be some code error that not showing the real flag.Continue Analyze it in dnspy.

![img](assets/writeups/Rawsec/7.png)

![img](assets/writeups/Rawsec/2.png)

![img](assets/writeups/Rawsec/3.png)

![img](assets/writeups/Rawsec/4.png)

![img](assets/writeups/Rawsec/5.png)

![img](assets/writeups/Rawsec/6.png)

Next continue analyze in dnspy and we found the error.The code show it only print flag1,2,3,4,5 while the flag is actually 6 in total.so flag 6 might be containing the real flag .Modify the code to print flag 6 and we get the flag.


![img](assets/writeups/Rawsec/10.png)

![img](assets/writeups/Rawsec/9.png)

 Replace it to flag6 to print the output . Run again the Program. Click showflag button untill you find flag6 which is real flag.

 ![img](assets/writeups/Rawsec/11.png)

The flag is : WSCTF2021{XOR1NG_IM4G35}


















