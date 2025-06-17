---
title: "RK 800 2024 -Writeup"
date: 2024-10-15
categories: [CTF, Writeup]
tags: [CTF,Osint]
image: assets/writeups/Curtin/C1.png
---

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




