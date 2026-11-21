# INE Assessment Methodologies: Footprinting & Scanning CTF 1
**Tools:**  ‘nmap’,  FireFox,  ‘curl’ , ‘mysql’
---
##Step 0:  Scan the target
‘‘’’
nmap -sC -sV <Target-IP>
‘’’
<img width="763" height="438" alt="image" src="https://github.com/user-attachments/assets/e2bb3f73-b16f-4c1a-94a5-f10adc4bdeb0" />

**Why:**  before testing any service I need to know what is running. Each open port is a possible way in, so the scan decides everything that follows.	
---
---
##Flag1: Custom HTTP Server header:
> Hint : The server proudly announce its identity in every response.
** What I did:** read the ‘fingerprint-strings’ section of the port 80 results in the Nmap output
<img width="711" height="275" alt="image" src="https://github.com/user-attachments/assets/cdd887f8-2fdf-4daf-93fb-2dd2502f05a7" />

**How it works:** A server normally sends oe header susch as ‘Server: Werkzeug/3.0.6 Python/3.10.12’. This is called banner grabbing: reading what a service says about itself. You can confirm with ‘ curl -I http://<Target-IP>’, which prints only the response headers.
**Results:** The response contained a **second** ‘Server’ header, and it held the flag.
---
---
##Flag2: ‘robots.txt’
>  Hint: The gatekeeper's instructions often reveal what should remain unseen. Don't forget to read between the lines.
**What I did:** opened ‘http://<Target-Ip>/robots.txt’ in Firefox.
<img width="940" height="358" alt="image" src="https://github.com/user-attachments/assets/fbca1623-d6c8-4884-bbc0-0783348efdde" />

**why:** “The gatekeeper’s instructions” describes the file that tells the crawler where not to go. It is always at the same location, so it’s a quick check on any web target.
**How it works:** the Robots Exclusion Protocol is a plain-text file at the web root:
‘’’
User-agent: *
Disallow: /secret-info/
Disallow: /data/
‘’’
‘User-agent’ says which crawler rule applies to (‘*’ is all), and ‘Disallow’  lists paths to skip.
** Result:** it listed  the following, `/photos` (Googlebot only), `/secret-info/` and `/data/`. I visited `/secret-info/`, which returned a JSON listing containing `flag.txt`.
‘’’  
‘http://<target-ip>/secret-info/flag.txt’
'''
<img width="940" height="226" alt="image" src="https://github.com/user-attachments/assets/1f09c254-8771-46be-9844-c3c97b69a217" />

---
---
##Flag3 : Anonymous FTP
>  Hint:  Anonymous access sometimes leads to forgotten treasures. Connect and explore the directory; you might stumble upon something valuable.
**What I did:** Listed the FTP root and read ‘flag.txt’ with ‘curl’.
‘’’
curl ftp://<anonymoususer:<userpassword>@<target-ip>/
curl ftp://<anonymoususer:<userpassword>@<target-ip>/flag.txt
‘’’
<img width="770" height="396" alt="image" src="https://github.com/user-attachments/assets/39f0ab38-a80a-451e-98ea-39d147a0abcc" />

**Why:** The Nmap scan had shown  that  ‘Anonymous FTP login allowe(FTP code230)’, so FTP was the obvious next service to enumerate .
**How it works:** anonymous FTP lets anyone log in with username ‘anonymous’ and any password. ‘curl’ accepts FTP URLs in the form ‘ftp://user:pass@host/path’. A URL ending in ‘/’ lists the directory, and a URL ending in a filename downloads the file . The permissions ‘-rw-r—r—’ mean anyone can read the files, including anonymous user.
---
---
> Hint: A well-named database can be quite revealing. Peek at the configurations to discover the hidden treasure.
**What I did:** read the other file from the FTP server, ‘creds.txt’.
‘’’
curl ftp://<anonymoususer:<userpassword>@<target-ip>/creds.txt
‘’’
<img width="940" height="349" alt="image" src="https://github.com/user-attachments/assets/540e11b9-440c-429d-a628-bdaa42f54ce2" />

**Why:** A file with the name on a public share is a finding on its own, and Nmap had shown a database service on port 3306.
**Results** The file held a database username and password in plain text. I used them to log in:
‘’’
mysql -h <target-ip> -P 3306  -u db_admin -p
‘’’
<img width="940" height="257" alt="image" src="https://github.com/user-attachments/assets/ac3f42d9-54bb-4980-bf07-8b84e93c6871" />

**How it works:**
Option		Meaning
‘-h’		host to connect to 
‘-P’		port(3306 is the default)
‘-u’		username
-p		prompt for the password, so it isn’t saved in shell history
The login worked, which is credential reuse: a file found on the FTP unlocked a different service. ‘SHOW TABLES;’ failed with ‘ERROR 1046: No database selected’, because tables live inside databases. So I listed the database instead:
‘’’
SHOW DATABSES;
‘’'
![Uploading image.png…]()
---
---
##Attack chain
‘’’
Nmap scan
  |-- Port 80   -> duplicate Server header ............... Flag 1
  |              -> robots.txt -> /secret-info/ .......... Flag 2
  |-- Port 21   -> anonymous FTP -> flag.txt ............. Flag 3
  |              -> creds.txt (database login)
  '-- Port 3306 -> login with FTP creds -> SHOW DATABASES . Flag 4
‘’’
---




