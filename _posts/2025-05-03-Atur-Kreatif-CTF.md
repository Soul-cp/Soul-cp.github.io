---
title: "AturKreatif CTF 2025 - Writeup"
date: 2025-05-03
categories: [CTF, Writeup]
tags: [Reverse Engineering, forensic, boot2root, web,]
image: assets/writeups/AKCTF/AKCTF25.png
---
## WEB

### 🍪 Challenge: Cookie Value (Web)

This web challenge revolves around modifying the **browser cookies**  a play on the word "**C0||oo||keys**" based on the challenge title and description.

---

#### 🔎 Initial Observation

Upon opening the challenge site and inspecting it using **F12 Developer Tools**, I noticed that **no cookies** were present in the `Application > Storage > Cookies` section.

 

---

#### 🧠 Hint Analysis

The challenge description reads:

> _"John Hammond likes to eat C0||oo||keys."_

This clearly hints that:
- The name of the cookie should be `C0||oo||keys`
- Possibly, the value should be something meaningful — let's try `1` (to indicate "true" or "yes")

---

#### 🛠️ Cookie Injection

Manually added a cookie:
- **Name:** `C0||oo||keys`
- **Value:** `1`

![Cookie added](/assets/writeups/AKCTF/JOHN.png)

After saving the cookie, I refreshed the page.

---

#### 🎉 Result

Upon refresh, the flag was revealed on screen:

![Flag found](/assets/writeups/AKCTF/flag.png)

✅ **Flag:** `AKCTF25{ch0c_ch1p_c00k13s_4r3_my_fav0ur1t3}`

---

#### 🔐 Vulnerability Type

This is a classic example of a **Client Side Authentication Bypass** via **manipulated cookies**. The server likely checks for the existence and value of a cookie before displaying the flag — without secure validation or encryption.

## 🧪 Forensics

### 🔍 Challenge Name: *Mimicats*

**DESCRIPTION**
Someone’s been meow-nipulating image files to send secrets. I think they’re using cute cats to hide something dangerous. I’m scared but also intrigued. Find out what they’re hiding, detective.

### 🐾 Step by Step Analysis

I start by analyzing the given `.pcap` file using Wireshark. Navigate to `Statistics > Protocol Hierarchy`. You’ll notice the file contains mostly TCP data, and 97.2% of it is JPEG image data (JFIF).

![wireshark](assets/writeups/AKCTF/Wireshark.png)

Next, apply the display filter:tcp.stream eq 0

You'll see a conversation that a hints that they use of an HTTP server to transfer images and a hidden file named billy.enc.

![wireshark](assets/writeups/AKCTF/tcp.png)

![wireshark](assets/writeups/AKCTF/conversation.png)

---

### 🖼️ Exporting Images

Use `File > Export Objects > HTTP` in Wireshark to save all `.jpg` files sent over the HTTP connection. You’ll find lots of cute cat images, but the key point is to identify which one contains `billy.enc`.

---

### 🪤 Decoy Flag Trap

First, try grepping through strings in the images to spot any hidden clues:

```shell
for f in *.jpg; do
  if strings "$f" | grep -iq "flag"; then
    echo "[FOUND] $f"
    strings "$f" | grep -i "flag"
    echo ""
  fi
done

This returns:

```sh
[FOUND] imposter.jpg
here is your flag, congratss aGVyZSBpcyB5b3VyIGZsYWcsIGNvbmdyYXRzcyBodHRwczovL3d3dy55b3V0dWJlLmNvbS93YXRjaD92PUw4WGJJOWFKT1hr
```
After decoding with Base64, I get a YouTube video just a meme. This is a red herring meant to throw off analysis.

I run binwalk -eM *.jpg to recursively scan the .jpg files and extract embedded data.Among the output, I discover that one of the cat images contains a file called billy.enc.

![billy.enc](assets/writeups/AKCTF/billy.png)

Next, place dec.py, keyfile.bin, and billy.enc in the same folder. Then run dec.py. If the script executes successfully, it will generate a file named decrypted.c. Use the `ls` command to verify the file exists, then use `cat` decrypted.c to read its contents and retrieve the flag.

![billy.enc](assets/writeups/AKCTF/python.png) 
![flag](assets/writeups/AKCTF/final.png)

heres your flag AKCTF25{C4ts_mEow_3il1y}

## 🌐 Boot2Root

### 🔓 Challenge Name: *NoteToRoot*

***Description***
The path starts with discovery. First things first, find the IP address to this box. Only then can you begin to uncover its secrets and follow the trail.

First Given the ova file  import it on vmware choose open a virtual machine and choose NoteToroot.ova 

![vm](assets/writeups/AKCTF/vm.png)

![vm](assets/writeups/AKCTF/vm2.png)

From the description the first thing we need to know is the ip address of the machine . Use `sudo netdiscover` from kali to know the ip machine of notetoroot .This is the  Reconnaissance (Info Gathering) the first step.

![vm](assets/writeups/AKCTF/vm3.png)

After know the ip address use command `ping`to check connection with the box. Next use tools nmap to see which port is open use command `nmap -A 192.168.22.58 ` and the result show that there are 2 port open ftp and ssh.

![vm](assets/writeups/AKCTF/vm4.png)

As you can see the result show that the ftp port is open also can login using anonymous and pasword:null 

![vm](assets/writeups/AKCTF/vm5.png)

After succesfully connect to ftp must enter passive mode first then you can check there are two file using command `ls` and use `get` to take the file from notetoroot machine to your kali machine.use `cat` to check the file contain, for user.txt you get the first flag and for user-note.txt you get the credential.

![vm](assets/writeups/AKCTF/vm6.png)

![vm](assets/writeups/AKCTF/User7.png)

### This is the second challenge

NoteToroot II

**Description**
The privileges you gain are merely borrowed. To claim true ownership requires exploiting the trust the system places in certain operations.

Author: lilacj4de

 I try to go to port ssh after get the credential but it display permision denied when I try to login. so go to notetoroot box and login as credential given.After log in run command sudo -i to open a root login since the description mentioning about privileges .I assume that we must get root access.

  ![vm](assets/writeups/AKCTF/vm8.png)

  the output show 

  ```shell
  User akctf25user may run the following commands on akctf25-b2r:
    (ALL) NOPASSWD: /usr/bin/find
  ```
## ✅ This means:
The user akctf25user can run the find command as root using sudo, without needing a password.

## 🔓 How to escalate to root:
You can exploit this with the -exec option in find, which allows you to execute a command and since you're allowed to run find as root, the command it runs will also be root. Run this

```shell
sudo /usr/bin/find . -exec /bin/bash \;
```
This will drop you into a root shell.Then confirm using command `whoami`.

 ![vm](assets/writeups/AKCTF/vm9.png)

 Next go to root priveleges to get to second flag

 ![vm](assets/writeups/AKCTF/vm10.png)

 ## 🔍 Reverse Engineering

### 🔧 Challenge Name: *HideNSeekWithMe*

**Description:**  
Our team intercepted this suspicious Android APK. Rumor says it hides a secret password and a flag. Can you reverse it to find the correct password and reveal the flag?

**Approach:** 
First decompile the file using jadx-gui because the file is .apk

![vm](assets/writeups/AKCTF/HAS.png)

Next go to /com this is home to soure code including Mainactivity, helper class, logic validator.

![vm](assets/writeups/AKCTF/HAS1.png)

this line show that 

{% highlight java %}
public native boolean verifyPassword(String str);
public native String getFlagNative(String str);

static {
    System.loadLibrary("native-lib");
}
{% endhighlight %}

The password is verified in the native C/C++ code in the libnative-lib.so file.So next approach I use ghidra to dissamble the  libnative-lib.so and there is a funcion getplainpassword.From there you know what the password is

![vm](assets/writeups/AKCTF/HAS2.png)

Open the hideseek.apk and put the password ***n1nj4_p3nyu***. Anotherway to solve this just decode the encoded flag in function getencodedflag

![vm](assets/writeups/AKCTF/HAS5.png)

![vm](assets/writeups/AKCTF/HAS3.png)

![vm](assets/writeups/AKCTF/HAS4.png)

## 🧠 Reflection

The AturKreatif CTF 2025 was an engaging and enriching experience. Each challenge offered a different flavor of cybersecurity — from cookie manipulation in the web challenge, steganographic investigation in forensics, deep system access in Boot2Root, to binary reverse engineering on Android.

The **Boot2Root** challenge stood out the most, simulating a real world pentest scenario where enumeration, exploitation, and privilege escalation were all required. Meanwhile, the **forensic task** honed my skills in network traffic analysis and hidden data extraction, emphasizing the importance of attention to detail in incident response. The **reverse engineering** challenge was a great test of my ability to dissect native Android code and apply static analysis tools like Ghidra effectively.

Overall, this CTF was a well balanced mix of fun, learning, and technical depth definitely looking forward to the next one!












