---
title: "n00bst3am CTF 2024 - Full Writeup"
date: 2024-07-24
categories: [CTF, Writeup]
tags: [ihack24, Reverse Engineering, malware, web, IDOR]
image: assets/writeups/Ihack/Ihack.png
---

## 🔁 Reverse Engineering

### 🧩 Challenge Name: CrackMe

**Description:**  
Your manager lost his license key. You are assigned to find the license key to activate Windows software. Crack the code, forge the key, and claim the access!

---

After extracting `CrackMe.zip`, we get several files:

![img](assets/writeups/Ihack/ihack13.png)

We focus on `CrackMe.dll` and `CrackMe.exe`. Using **dnSpy**, `CrackMe.dll` provides the most useful lead.

Inspecting the `Forum1` class, we find an encrypted license key:

![img](assets/writeups/Ihack/ihack14.png)  
![img](assets/writeups/Ihack/ihack15.png)

> Encrypted License: `BRQFHF@WR_+6,N:$78`  
> XOR Key: `secret`

Using Python, we XOR-decrypt it and get:

✅ `1724-2321 NBSI-HACK`

![img](assets/writeups/Ihack/ihack16.png)

Test it inside the application:

![img](assets/writeups/Ihack/ihack17.png)

Confirmed valid. Final flag:  
✅ **Flag:** `ihack24{1724-2321-NBSI-HACK}`

---

## 🔍 DFIR (Digital Forensics Incident Response)

### 🧩 Challenge Name: Lock?

We’re given `artefact.tar.gz`. Extract it using:

```bash
tar -xzvf artefact.tar.gz
```

Now we have 4 files:

![img](assets/writeups/Ihack/ihack19.png)

Opening `storageM.img` prompts for a password.

We inspect the `.evtx` log files. Using a log viewer, we locate the password inside `WindowsPowerShell.evtx`:

![img](assets/writeups/Ihack/ihack21.png)  
![img](assets/writeups/Ihack/ihack22.png)

> Password: `pa55iPOjLKbMN`

Use it to unlock `storageM.img`. Upon decryption, we retrieve 3 files:

![img](assets/writeups/Ihack/ihack23.png)

Open `flag.txt`:

![img](assets/writeups/Ihack/ihack24.png)

✅ **Flag:** `ihack24{6f6450f1695e405557486a2be402dc27}`

---

## 🌐 Web Exploitation

### 🧩 Challenge Name: Character Journey

The challenge presents a login portal.

![img](assets/writeups/Ihack/ihack25.png)  
![img](assets/writeups/Ihack/ihack26.png)

Inspecting `/myaccount`, we spot a user ID parameter — classic **IDOR (Insecure Direct Object Reference)**.

We write a Python script to iterate user IDs and look for `admin`:

![img](assets/writeups/Ihack/ihack27.png)

✅ **Flag:** `ihack24{655b7b7ae4c62d726a568eff8914573e}`

---

### 🧩 Challenge Name: My Memo

![img](assets/writeups/Ihack/ihack28.png)

After visiting the site:

![img](assets/writeups/Ihack/ihack29.png)  
![img](assets/writeups/Ihack/ihack30.png)

We register and inspect the network tab. Creating a memo sends a request to the server.

We write a Python script to dump credentials:

![img](assets/writeups/Ihack/ihack31.png)

We log in as `admin71800` and explore hidden sections:

![img](assets/writeups/Ihack/ihack32.png)  
Clicking hidden sections reveals internal notes:

![img](assets/writeups/Ihack/ihack33.png)

Eventually, we reach the note containing the flag:

![img](assets/writeups/Ihack/ihack34.png)  
![img](assets/writeups/Ihack/ihack35.png)  
![img](assets/writeups/Ihack/ihack36.png)

---
