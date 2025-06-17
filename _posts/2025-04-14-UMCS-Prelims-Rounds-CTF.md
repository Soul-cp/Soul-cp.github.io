---
title: "UMCS CTF 2025"
date: 2025-04-14
categories: [CTF]
tags: [CTF]
image: assets/writeups/UMCS/U1.png
---

## Challenge name : Hidden in Plain Graphic
## Category : Forensic

![img](assets/writeups/UMCS/U2.png)

The challenge gives plain_zight.pcap file for us to analyze. Further analysis we found sus file on line 562 with long length. The file that contains long length

![img](assets/writeups/UMCS/U3.png)

we see that there is file header. upon searching the file, it is a Png file copy and paste the byte in
hex edit and save the file.

![img](assets/writeups/UMCS/U4.png)

![img](assets/writeups/UMCS/U5.png)

Next upload the file in AperiSolve to analyze the image and found flag.png

![img](assets/writeups/UMCS/U6.png)

When scroll we found the flag in zsteg command 

![img](assets/writeups/UMCS/U7.png)

Flag:umcs{h1dd3n_1n_png_st3g}

## Challenge name : Healthcheck
## Category : Web


![img](assets/writeups/UMCS/U8.png)

We were given a website link, and a description of the challenge that says we need to fetch the hopes_and_dreams inside the server. So key here we need to retrieve the file from the server.

![img](assets/writeups/UMCS/U9.png)

So interning there is the box there that ask us to enter URL and button “Check”. As the description of the challenge it say fetch.

![img](assets/writeups/UMCS/U10.png)

I try to insert the challenge URL to see the response. It’s just display response code. Pretty common challenge for web, where it checks pages and displays the output. But this time it only displays Response code. I try multiple attempts to see if we can get any response if we replace it with localhost. Turns out it was nothings no response at all.

From previous challenge where it gives GitHub link I found a folder that say “web-health check"

![img](assets/writeups/UMCS/U11.png)


Inside it is just a description of the challenge and index.php.

![img](assets/writeups/UMCS/U12.png)

I checked on the index.php file and found this. It has sanitized function where its blocks or blacklist multiple symbols. All those symbols are quite common that use for command injections.

![img](assets/writeups/UMCS/U13.png)

This part right here, is key to our exploitation. Why did i say so? It is because it carry the sanitized_url and execute command using curl to check the status server and after that it grep the response status. As long as we can avoid all the blacklist symbol we can bypass and pull the files from the servers. So here the comes the payload since it runs execute curl command and grep, its is impossible to use other command like cat or strings to see the content flag. So in this case we need 1 sever to use as listener, this can be webhook or any other than that.

![img](assets/writeups/UMCS/U14.png)

Our plan here is to post or submit the payload through the check form. Before that we need to make sure that we do not trigger or use any blacklist symbol. As i say we need to post, and the command that use to executed is curl so we can use –F to submit the specific file to the listener(Webhook).

![img](assets/writeups/UMCS/U15.png)

The payload is like this, we need to specify our webhook URL, this is important otherwise we can’t pull the flag. Since it execute curl command we can utilize the function here by using options –F to post or submit the file to our webhook. As the question say, we need to retrieve the file name “hopes_and_dreams”.

![img](assets/writeups/UMCS/U16.png)

So we submit to see the response code. Now we can confirm that the command has been executed without any issue. How did we confirm that? It is by the response code It return HTTP/1.1 100 HTTP/1.1 200.

![img](assets/writeups/UMCS/U17.png)
![img](assets/writeups/UMCS/U18.png)

HTTP/1.1 100 here indicates that our webhook has receive the file that we just post. While HTTP/1.1 200 here indicates that it OK, means request has been process without any issue.

![img](assets/writeups/UMCS/U19.png)

![img](assets/writeups/UMCS/U20.png)

Okay now we check on the webhook and as expected we should get the file that we just post from the challenge server. We can download the hopes_and_dreams and save it as text file to see what's content inside.

![img](assets/writeups/UMCS/U21.png)

FLAG = umcs{n1c3_j0b_ste4l1ng_myh0p3_4nd_dr3ams}

## Challenge name : Gist of samuel
## Category : Crypto

![img](assets/writeups/UMCS/U22.png)

Upload to gpt , to decode it into morse code. the script give us 3 mappings and the correct one is a direct clue  

![img](assets/writeups/UMCS/U23.png)

```python
def decode_morse_trains(train_text):
    # Define all three mappings
    mapping1 = {'🚂': '.', '🚆': '-', '🚋': ' '}
    mapping2 = {'🚂': '-', '🚆': '.', '🚋': ' '}
    mapping3 = {'🚂': '.', '🚋': '-', '🚆': ' '}

    # International Morse code dictionary
    morse_code_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '-----': '0',
        '--..--': ',', '.-.-.-': '.', '..--..': '?', '-..-.': '/',
        '-.--.': '(', '-.--.-': ')', '.-...': '&', '---...': ':',
        '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-',
        '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
        '-.-.--': '!'
    }

    results = []
    for mapping_name, mapping in [("Mapping 1", mapping1), ("Mapping 2", mapping2), ("Mapping 3", mapping3)]:
        morse_code = ''
        for char in train_text:
            if char in mapping:
                morse_code += mapping[char]

        morse_letters = morse_code.strip().split(' ')
        decoded_text = ''
        for symbol in morse_letters:
            if symbol in morse_code_dict:
                decoded_text += morse_code_dict[symbol]
            elif symbol:
                decoded_text += '?'
        results.append((mapping_name, decoded_text.strip()))
    return results

# Read the emoji train text from file
with open('/home/ubuntu/upload/gist_of_samuel.txt', 'r') as file:
    train_text = file.read()

# Decode using different mappings
results = decode_morse_trains(train_text)

# Print results
for mapping_name, decoded_text in results:
    print(f"{mapping_name}: {decoded_text}")
```
The output give us a hint to next step

![img](assets/writeups/UMCS/U24.png)

Mapping 3:
HERE?IS?YOUR?PRIZE?E012D0A1FFFAC42D6AAE00C54078AD3E?SAMUEL?REALL Y?LIKES?TRAIN,?AND?HIS?FAVORIT?NUMBER?IS?8

Next unlock the hint , We know that this is one of the E012D0A1FFFAC42D6AAE00C54078AD3E gist github link.

![img](assets/writeups/UMCS/U25.png)

We need to decode it to get the flag , I confirm this is the RAIL FENCE WITH THE HINT MY FAVORITE NUMBER IS 8, which is the rail and offset is set 0 I try so many tools but all of it are like distortion. Lastly, I using
Cache Sleuth - Rail Fence Cipher and get the flag name of the campsite 

![img](assets/writeups/UMCS/U26.png)

Flag : umcs{willow_tree_campsite}

## Challenge name : http-server
## Category : Reverse Engineering

![img](assets/writeups/UMCS/U27.png)

This challenge is direct. if give match input as the server request it will retrieve flag , Download the file and put in on Ida , disassemble it is using f5 and find function sub1548.the function after main. The function here says that if our input match their condition it will open /flag so just input the syste ask and get the flag.

![img](assets/writeups/UMCS/U28.png)

GET /goodshit/umcs_server HTTP/13.37 if input this it will retrieve the flag

![img](assets/writeups/UMCS/U29.png)



















