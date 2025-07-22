---
title: "HTB : CTF TRY OUT"
date: 2025-07-08
categories: [CTF, Writeup]
tags: [Reverse Engineering]
image: assets/writeups/HTB/htb1.png
---

## 🧩 Reverse Engineering

**Challenge Name**: **FlagCasino**

### 🎯 Description

The team stumbles into a long-abandoned casino. As you enter, the lights and music whir to life, and a staff of robots begin moving around and offering games, while skeletons of prewar patrons are slumped at slot machines. A robotic dealer waves you over and promises great wealth if you can win - can you beat the house and gather funds for the mission?

The file provided was named casino, and it was an executable binary. The first thing I did was run the `file` and `strings` commands to identify the file type and extract any printable ASCII strings from it.

![img](assets/writeups/HTB/htb2.png)

![img](assets/writeups/HTB/htb3.png)

After running the casino executable, I was greeted with some flashy ASCII art of a robot and a prompt that read: `PLACE YOUR BETS`. Out of curiosity, I tried some random inputs like `'a' and '1'`, but each attempt returned  `[ * INCORRECT * ]`, followed by a dramatic warning that the `SECURITY SYSTEM` had been activated. Clearly, the program was expecting something very specific  a precise sequence of characters to pass its checks. The challenge now was figuring out exactly what those inputs were to outsmart the house.

![img](assets/writeups/HTB/htb4.png)

🛠️ Initial Analysis with IDA
I opened the casino binary in IDA to figure out how it worked. As usual, the main() function was the place to start — it holds the core logic of most binaries.

🧠 Decompiled Logic (IDA View)
The core logic was in main(). Here’s a simplified view of what it does:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+Bh] [rbp-5h] BYREF
  unsigned int i; // [rsp+Ch] [rbp-4h]

  puts("[ ** WELCOME TO ROBO CASINO **]");
  // ... (ASCII art output) ...
  puts("[*** PLEASE PLACE YOUR BETS ***]");

  // The core challenge logic is within this loop
  for ( i = 0; i <= 0x1C; ++i ) // Loop runs 29 times (i from 0 to 28)
  {
    printf("> ");
    if ( (unsigned int)__isoc99_scanf(" %c", &v4) != 1 ) // Reads a single character input
      exit(-1);

    srand(v4); // Seeds the random number generator with the input character

    if ( rand() != check[i] ) // Checks if the first generated random number matches a value from 'check' array
    {
      puts("[ * INCORRECT * ]");
      puts("[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]");
      exit(-2); // Exits if the random number does not match
    }
    puts("[ * CORRECT *]"); // Continues if correct
  }
  puts("[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]"); // Success message
  return 0;
}
```
That loop runs 29 times (i = 0 to 28). For each round:
- It asks for one character of input (scanf(" %c", &v4)).
- Seeds the RNG using that character (srand(v4)).
- Calls rand() once and compares the result to check[i].

If the value matches, it prints [ * CORRECT * ] and continues.
If not, it prints [ * INCORRECT * ] and shuts down the program.

At the end of all 29 successful inputs, it prints:

```shell
[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]
```

![img](assets/writeups/HTB/htb5.png)

🔓 Identifying the Vulnerability: Predictable Randomness
The core of this challenge lies in the nature of srand() and rand():

🎲 Pseudorandom Isn't Really Random
The rand() function doesn’t produce true randomness. Instead, it generates a deterministic sequence based entirely on the seed passed to srand().

So, if I call srand(65) (for example), the first rand() output will always be the same — no matter how many times I run it.

🧩 The Core Check
In this binary, each of the 29 input characters gets passed as a seed to srand(). Right after that, rand() is called and the result is compared to check[i].

To pass a round, the output of rand() must exactly match the value at check[i].

So the task becomes:

For each check[i], find a character c where srand(c) → rand() returns check[i].

📦 Extracting check[] Values
To start solving this, I needed the actual values the binary expected. I opened the .data section in IDA and found the check array.

That array held 29 hardcoded integers the exact outputs rand() should produce if seeded correctly.

![img](assets/writeups/HTB/htb6.png)

The check array was defined as _DWORD check[29] and contained the following 29 32-bit hexadecimal integer values:

```
0x244B28BE, 0x0AF77805, 0x110DFC17, 0x07AFC3A1, 0x6AFEC533,
0x4ED659A2, 0x33C5D4B0, 0x286582B8, 0x43383720, 0x055A14FC,
0x19195F9F, 0x43383720, 0x63149380, 0x615AB299, 0x6AFEC533,
0x6C6FCFB8, 0x43383720, 0x0F3DA237, 0x6AFEC533, 0x615AB299,
0x286582B8, 0x055A14FC, 0x3AE44994, 0x06D7DFE9, 0x4ED659A2,
0x0CCD4ACD, 0x57D8ED64, 0x615AB299, 0x22E9BC2A

```
With the check[] values extracted, the next step was figuring out which input character would trigger each expected rand() output.

To do this, I wrote a Python script that brute-forces all possible single-byte inputs (0–255) for each target value.

The script uses Python’s ctypes library to directly call srand() and rand() from the system’s C standard library — making sure it behaves exactly like the original binary.

```python
import ctypes

# Load the C standard library (libc) - adjust path for your OS
libc = ctypes.CDLL("libc.so.6") # Example for Linux
libc.rand.restype = ctypes.c_int

# The check array values extracted from IDA
check_values = [
    0x244B28BE, 0x0AF77805, 0x110DFC17, 0x07AFC3A1, 0x6AFEC533,
    0x4ED659A2, 0x33C5D4B0, 0x286582B8, 0x43383720, 0x055A14FC,
    0x19195F9F, 0x43383720, 0x63149380, 0x615AB299, 0x6AFEC533,
    0x6C6FCFB8, 0x43383720, 0x0F3DA237, 0x6AFEC533, 0x615AB299,
    0x286582B8, 0x055A14FC, 0x3AE44994, 0x06D7DFE9, 0x4ED659A2,
    0x0CCD4ACD, 0x57D8ED64, 0x615AB299, 0x22E9BC2A
]

result_string = ""
print("Finding the correct input characters...")

for i, target_value in enumerate(check_values):
    found_char = None
    for char_code in range(256):
        libc.srand(char_code)
        first_rand_value = libc.rand()
        
        if first_rand_value == target_value:
            found_char = chr(char_code)
            result_string += found_char
            break
    
    if found_char is None:
        print(f"[!] ERROR: Could not find a seed for check_values[{i}] = {hex(target_value)}")
        result_string = ""
        break

if result_string:
    print("\n[+] Success! The full input string is:")
    print(result_string)
else:
    print("\n[!] Failed to generate the complete input string.")    
```

🎉 Executing the Solution
After running the Python brute-force script (juk.py), I finally got the full 29-character input string:

HTB{r4nd_1s_v3ry_pr3d1ct4bl3}

![img](assets/writeups/HTB/htb7.png)

This result were input to ./casino and the result confirmed that all 29 "bets" were correct, and the casino's balance hit zero!

![img](assets/writeups/HTB/htb8.png)

🧾 Conclusion

This one was pretty straightforward but still satisfying. The whole challenge hinged on how rand() behaves when seeded with predictable input  something you don’t usually think much about until it breaks a whole program.

Once I saw that each character input was used as a seed and compared to a fixed value, it was just a matter of scripting out the brute force and matching everything up.

The flag is HTB{r4nd_1s_v3ry_pr3d1ct4bl3}

**Challenge Name**: **Don't Panic!**

### 🎯 Description

You've cut a deal with the Brotherhood; if you can locate and retrieve their stolen weapons cache, they'll provide you with the kerosene needed for your makeshift explosives for the underground tunnel excavation. The team has tracked the unique energy signature of the weapons to a small vault, currently being occupied by a gang of raiders who infiltrated the outpost by impersonating commonwealth traders. Using experimental stealth technology, you've slipped by the guards and arrive at the inner sanctum. Now, you must find a way past the highly sensitive heat-signature detection robot. Can you disable the security robot without setting off the alarm?

Given a file named dontpanic, when I use the file command, it shows that it's a simple ELF file. When I run strings, it looks like a Rust binary. To confirm this, I used DIE (Detect It Easy) to check which programming language the file was written in.

![img](assets/writeups/HTB/htb10.png)

![img](assets/writeups/HTB/htb11.png)

![img](assets/writeups/HTB/htb9.png)

Upon examining the provided binary , our primary goal was to find a hidden flag. We were given a snippet of assembly code 

The key function identified was src::check_flag::h397d174e03dc8c74(__int64 a1, __int64 a2). This function is interest me because functions named "check_flag" are almost always involved in validating an input string against a secret.

```c
__int64 __fastcall src::check_flag::h397d174e03dc8c74(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  __int64 v3; // r14
  __int64 v4; // [rsp+0h] [rbp-148h] BYREF
  __int64 v5; // [rsp+8h] [rbp-140h] BYREF
  __int64 v6[31]; // [rsp+10h] [rbp-138h] // <--- This array is crucial!
  __int64 v7[8]; // [rsp+108h] [rbp-40h] BYREF

  // ... (Initialization of v6 array with function pointers) ...

  v4 = a2;
  v5 = 31LL;
  if ( a2 != 31 ) // Length check
  {
    v7[0] = 0LL;
    core::panicking::assert_failed::hb9915114bebb1f93(&v4, &v5, v7);
  }
  result = 0LL;
  do
  {
    v3 = result + 1;
    ((void (__fastcall *)(_QWORD))v6[result])(*(unsigned __int8 *)(a1 + result)); // Loop calling functions
    result = v3;
  }
  while ( v3 != 31 );
  return result;
}
```
🧠 Key Observations
📌 Parameters
a1 — likely a pointer to the flag buffer (user input).

a2 — the length of the input buffer.

🔐 Length Check
The function immediately checks if a2 == 31. If not, it calls a Rust panic handler and exits. So, the input must be exactly 31 characters long — that's the expected flag length.

🧩 Function Pointer Array (v6)
The array v6[31] holds 31 function pointers — one for each byte of the flag.

These functions are Rust-generated and heavily mangled, like core::ops::function::FnOnce::call_once::h....

🔁 Loop Behavior
A do-while loop runs 31 times.

In each iteration:

It grabs the current character from the input string:
*(unsigned __int8 *)(a1 + result)

It then calls the corresponding function in v6[result], passing that character as an argument.

If any of these functions panic or fail, the entire check_flag fails.

🧪 What This Means
Each character of the flag is individually validated by a separate function. If even one of them doesn't like its input, the flag is rejected.

The next step was to find the decompiled code for each of the unique function pointers stored in the v6 array. Fortunately, we obtained the decompiled C-like pseudocode for all of them.

Each validation function follows a very consistent pattern:

```c
void __fastcall __spoils<...> core::ops::function::FnOnce::call_once::hXXXXXXXXXXXXX(unsigned __int8 a1)
{
  if ( a1 < 0xYYu ) // Check 1: Is a1 less than a certain value?
    core::panicking::panic::h8ddd58dc57c2dc00(); // If yes, panic!
  if ( a1 != ZZZ ) // Check 2: Is a1 NOT equal to a certain value?
    core::panicking::panic::h8ddd58dc57c2dc00(); // If yes, panic!
}
```
🔎 Explanation of the Pattern
unsigned __int8 a1: Confirms that the function takes a single byte (character) as input.

core::panicking::panic::h8ddd58dc57c2dc00(): The Rust panic handler. If this gets called, the program terminates — meaning the input is wrong.

✅ How It Works
For the function not to panic, both if conditions must evaluate to false:

if (a1 < 0xYYu) being false → a1 must be greater than or equal to 0xYY

if (a1 != ZZZ) being false → a1 must be equal to ZZZ

Crucially, in every function, 0xYY (hex) is always the same as ZZZ (decimal).
So for the check to pass, a1 must be exactly equal to ZZZ.

### 🧩 Function Pointer Mapping Table

| Index | Function Hash              | ASCII (Hex) | Character |
|-------|----------------------------|-------------|-----------|
| 0     | h32497efb348ffe3c          | 0x48        | H         |
| 1     | h827ece763c8c7e2e          | 0x54        | T         |
| 2     | h784eba9476a4f0f4          | 0x42        | B         |
| 3     | hc26775751c1be756          | 0x7B        | {         |
| 4     | hc599f6727ca8db95          | 0x64        | d         |
| 5     | h40d00bd196c3c783          | 0x30        | 0         |
| 6     | h4e1d94269d5dab9f          | 0x6E        | n         |
| 7     | h1e50475f0ef4e3b2          | 0x74        | t         |
| 8     | h28c42c5fb55e3f9f          | 0x5F        | _         |
| 9     | h08f069e45c38c91b          | 0x70        | p         |
| 10    | h70ddab66eb3eaf7e          | 0x34        | 4         |
| 11    | h4e1d94269d5dab9f          | 0x6E        | n         |
| 12    | h5935cc8a67508b36          | 0x31        | 1         |
| 13    | h2ed86dfdd0fc9ca5          | 0x63        | c         |
| 14    | h28c42c5fb55e3f9f          | 0x5F        | _         |
| 15    | h2ed86dfdd0fc9ca5          | 0x63        | c         |
| 16    | h70ddab66eb3eaf7e          | 0x34        | 4         |
| 17    | h1e50475f0ef4e3b2          | 0x74        | t         |
| 18    | h2ed86dfdd0fc9ca5          | 0x63        | c         |
| 19    | h076f93abc7994a2b          | 0x68        | h         |
| 20    | h28c42c5fb55e3f9f          | 0x5F        | _         |
| 21    | h1e50475f0ef4e3b2          | 0x74        | t         |
| 22    | h076f93abc7994a2b          | 0x68        | h         |
| 23    | ha0a2d91800448694          | 0x65        | e         |
| 24    | h28c42c5fb55e3f9f          | 0x5F        | _         |
| 25    | hd3a717188d9c9564          | 0x33        | 3         |
| 26    | h4aee5a63c69b281c          | 0x72        | r         |
| 27    | h4aee5a63c69b281c          | 0x72        | r         |
| 28    | h3dae80a6281f81f5          | 0x6F        | o         |
| 29    | h4aee5a63c69b281c          | 0x72        | r         |
| 30    | he29dc24b9b003076          | 0x7D        | }         |

### 🏁 Final Flag

```
HTB{d0nt_p4n1c_c4tch_the_3rror}
```


