# honeypot-detector v1.0.1

## Usage
```bash
$ honeypot-detector -h
honeypot-detector v1.0.1 - (c) 2017 Jorge Matricali
usage: ./honeypot-detector [-l targets.lst] [-p port] [-j threads] [-t timeout] [-vh] [target]
```

```bash
$ honeypot-detector 192.168.0.26
[!] 192.168.0.26:22 - POSSIBLE HONEYPOT!
```

```bash
$ honeypot-detector -l targets.txt -j 4
[+] 192.168.0.87:22 - SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6
[+] 192.168.0.8:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1
[+] 192.168.0.52:22 - SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8
[+] 192.168.0.58:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[+] 192.168.0.191:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[+] 192.168.0.211:22 - SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2
[+] 192.168.0.124:22 - SSH-2.0-OpenSSH_7.2 FreeBSD-20160310
[!] 192.168.0.26:22 - POSSIBLE HONEYPOT!
[+] 192.168.0.73:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[+] 192.168.0.226:22 - SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.6
[+] 192.168.0.1:22 - SSH-2.0-OpenSSH_6.6.1
[+] 192.168.0.177:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[+] 192.168.0.157:22 - SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[+] 192.168.0.188:22 - SSH-2.0-OpenSSH_6.6.1
[!] 192.168.0.83:22 - POSSIBLE HONEYPOT!
[+] 192.168.0.147:22 - SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2
[+] 192.168.0.142:22 - SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.7
```
