### Data From Network Shared Drive [\[T1039\]](https://attack.mitre.org/techniques/T1039/)

Network shared drives are a treasure trove of sensitive corporate documents. Most enterprise networks host shared network drives using SMB, but some may rely on FTP, HTTP, or even RDP. Zeek can monitor access to shared network drives when protocols like SMB, FTP, or HTTP are used. Remote control protocols, like RDP, are also parsed in protocol-specific logs. Anywhere Corelight sees this traffic, it is monitored and logged in the protocol-specific log.

The following example demonstrates the `ftp` log. Corelight logs the command and arguments.

```
path: ftp
uid: C0EeI73um1Aw3rrOib
id.orig_h: 10.0.0.11
id.orig_p: 45831,
id.resp_h: 119.74.138.214
id.resp_p: 21,
user: 1
password: <hidden>
command: RETR
arg: ftp://119.74.138.214/doc.exe
reply_msg: Transfer OK
```

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Sensitive File Access Over SMB Share|https://tdm.socprime.com/tdm/info/2RUVrOzhI3gB |
|Sensitive File Access On Admin Network Share|https://tdm.socprime.com/tdm/info/tSQlh2fAPZ81 |
