### Remote Services [\[T1021\]](https://attack.mitre.org/techniques/T1021/)

Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error to execute adversary-controlled code. This exploitation can happen in a program, service, or within the operating system software or kernel itself. A common goal for post-compromise exploitation of remote services is for lateral movement.

Given the complexity of today's enterprise networks, a variety of third-party and external services are often in use. These services allow attackers to gain initial access or to move laterally. All connections are logged within the `conn` log, however, more details may be available within protocol-specific logs depending on the nature of the remote service under attack. For example, you can monitor the `http` log file for suspicious and unexpected HTTP requests (such as OPTIONS requests).

```
_path: http
uid: CEeVS92Ljnr9jbW2J5
id.orig_h: 54.235.163.229
id.orig_p: 41855
id.resp_h: 192.168.0.2
id.resp_p: 80
trans_depth: 1
method: OPTIONS
host: host-90-236-3-35.mobileonline.telia.com
uri: *
version:1.1
```

Additionally, Corelight extracts information about software observed on the network into the `software` log. This file provides defenders valuable data to monitor for unexpected or unauthorized servers, vulnerable or out-of-date services, and unpatched client software.

```
path: software
host: 192.168.0.53
software_type: SMTP::MAIL_CLIENT
name: Microsoft Outlook Express
version.major: 6
version.minor: 0
version.minor2: 2900
version.minor3: 5512
unparsed_version: Microsoft Outlook Express 6.00.2900.5512
```
