---
# INE Information Gathering CTF 1

A write-up of an INE lab where the goal is to capture 5 flags using **reconnaissance only** (no exploitation). For each step I explain what I did, why I did it, and how it works.

> Authorised training lab. Flag values are left out on purpose.

**Tools:** `ping`, Firefox, `nmap`, `dirb`
---
---
## Step 0: Confirm the host is alive

```
ping -c5 <TARGET_IP>
```
<img width="940" height="367" alt="image" src="https://github.com/user-attachments/assets/91854dac-cf43-4e0c-bf26-89215a3a406e" />


**Why:** before scanning anything, I need to know the target is reachable. Otherwise I could misread empty scan results from a machine that is simply offline.

**How it works:** `ping` sends ICMP Echo Requests and waits for Echo Replies. `-c5` stops after 5 packets (without it, Linux pings forever). The output shows packet loss, round-trip time, and the TTL, which hints at the operating system (Linux usually starts at 64, Windows at 128). That is a guess, not proof.

**Result:** the target replied, so it is up and reachable.

**Note:** no reply doesn't always mean the host is down, because firewalls often block ICMP. In that case I would scan with `nmap -Pn`.
---
---
## Flag 1: `robots.txt`

> Hint: this file tells search engines what to index and what to avoid.

<img width="940" height="374" alt="image" src="https://github.com/user-attachments/assets/2cb641ac-9553-4787-8f8c-ceeeacc9c20b" />

**What I did:** opened `http://<TARGET>/robots.txt` in Firefox.

**Why:** it's a quiet check that looks like a normal visitor request, and it often lists paths the owner doesn't want indexed.

**How it works:** the Robots Exclusion Protocol is a plain-text file at the web root:

```
User-agent: *
Disallow: /example-path/
```
---

---
##Flag 2: Identify the website and its version 
>Question: what website is running on target, and what is the version?
**Why:**  the technology and the version decide what to test next. Each platform has  its own layout and known vulnerabilities, and a specific version can be matched to public CVEs. This is called fingerprinting.


##Method A: view the page source
Press `CTRL +U `  in FireFox.
** How it works:** the browser renders HTML, but the raw source can contain comments, scripts and style sheet links, and `<meta` tags. CMS platforms often add a generator tag:
```
<meta name =”generator” content=”Wordpress x.y.z” />
```

Paths such as ‘/wp-content/’ are another sign of WordPress.

<img width="940" height="155" alt="image" src="https://github.com/user-attachments/assets/816ac622-de06-4355-97c5-352c4f50d302" />

##Method B: Nmap scripts and version detection.

<img width="940" height="348" alt="image" src="https://github.com/user-attachments/assets/0d4fed47-7a76-4abd-9108-a65094ef67d9" />

```
nmap <target-Ip>  -p80 -sC -sV 
```
Option	Meaning
`-p80`	scan only port 80(HTTP)
`-sC `	run Nmap’s default NSE scripts
`-sV` 	probe the service to identify its version

**How it works:** `-sV ` compares the server’s replies against Nmap’s signature database. `-sC` includes the `http-generator` script, which reads the generator tag from the page. The flag appeared next to the `http-generator` result, which showed **WordPress**. 
**Why use both:** they confirm each other. The source shows context, and Nmap gives repeatable output for a report.
**Defender’s view:**  Version disclosure helps attackers match a release to known exploits. Remove the generator tag, keep WordPress and plugins patched, and limit what response headers reveal.
---

---
##Flag 3: Directory browsing
> Hint directory browsing might reveal where files are stored.

<img width="914" height="634" alt="image" src="https://github.com/user-attachments/assets/2c6a8a19-282e-4f24-8ac7-35bebcab4cda" />

**What I did:** used ‘dirb’ to look for accessible files and directories on the web server.
```
dirb http://<TARGET-IP>/
```
<img width="799" height="527" alt="image" src="https://github.com/user-attachments/assets/ebd1c8bb-6602-4fec-9ad3-1376926f717d" />

**Why:** Websites often have content that isn’t linked from any page, such as uploads and old files. Enumeration finds what navigation hides.
**How it works:** ‘dirb’ takes a wordlist of common directories and file names, requests each one against the server and reports which exists based on the HTTP status code (for example `200` found, `301` redirect, `403` forbidden, `404` not found).
**Result:** http://<TARGET-IP>/wp-content/uploads/
<img width="940" height="441" alt="image" src="https://github.com/user-attachments/assets/3fcb90ed-079c-4edf-9323-0fbf6a89a26a" />

---

---
##Flag 4: Mirrored files
   > Hint: an overlooked backup file in the Webroot can be problematic if it reveals sensitive configuration details.
**What I did**
```
Dirb http:/<TARGET-IP>  -X  .bak, tar.gz, .zip
```

<img width="729" height="486" alt="image" src="https://github.com/user-attachments/assets/34faa403-bb5b-41ea-84f5-83e1106932c1" />

**Why:** Admins and editors often copy a config file before changing it( `wp-config.php` becomes `wp-config.bak`). The server runs `.php` files, so their source is never shown. A `.bak` file isn’t executed, so the web server hands over its raw content as plain text.
**How it works : ** the `-X` option tells dirb to append each extension to every  word in it’s wordlist. dirb used `usr/share/dirb/wordlist/common.txt` and requested each word with `.bak` added, so it tried names like ‘admin.bak’ and `wp-config.bak`.

```
curl http://target.ine.local/wp-config.bak
```

<img width="940" height="528" alt="image" src="https://github.com/user-attachments/assets/31c2e556-12a8-4faf-9b2a-4d19695f5fd3" />

**Result:** dirb found one hit : `http://<Target-Ip>/wp-config.bak`. Opening it showed the full WordPress configuration, including the authentication keys and salts, with the flag  hidden in the comments
---

---
##Flag 5: Mirrored files
> Hint: certain files may reveal something interesting when mirrored.
**What I did**
```
httrack <target-ip> -O  target.html
```

<img width="940" height="402" alt="image" src="https://github.com/user-attachments/assets/040135aa-b15a-4e03-b0b2-169c92dbf5da" />

**Why:** browsing a site only shows what the pages link to. Mirroring downloads everything the crawler can reach into a local folder, so I can search it with normal command-line tool like `find` and `grep`. That finds files I’d never click on, including non-visible files that the site generates.
**How it works:** HTTrack is a website copier. It starts at the homepage, follows links, and saves each page and asset locally. ‘-O target.hmtl’ sets the output folder. HTTrack warned me that I was running as root, which is fine in lab, but  in practice use a normal user. 

** I located the `xmlrpc0db0.php` in the mirror and read it with `cat`. It’s a an RSD(Real simple Discovery)  file, an XML document that WordPress publishes to list the APIs the site supports. The flag was hidden in one od the `<api name=…>` entries. HTTrack adds a short suffic to some saved filenames (like `0db0`), os the name differs from the original URL.

```
cat target.html/<target-ip>/xmlrpc0db0.php
```

<img width="940" height="485" alt="image" src="https://github.com/user-attachments/assets/36e4fe96-ed11-40d0-83a5-de622ac239ab" />
---
