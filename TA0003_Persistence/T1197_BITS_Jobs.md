### BITS Jobs [\[T1197\]](https://attack.mitre.org/techniques/T1197)

Microsoft Background Intelligent Transfer Service (BITS) was created in 2001 as a mechanism for managing file transfers that minimize disruption to the end user. BITS is commonly used to download Windows updates and other software updates from major vendors.

Attackers have two methods of abusing BITS:
- The most common is to create a BITS transfer job directly on a host, allowing a download of secondary payloads through a built-in Windows service that typically bypasses firewalls and other security controls.
- Another alternative is to exfiltrate data through a BITS upload job. Uploads must connect to an IIS server for BITS to function properly, but this requirement is trivial for malware authors to subvert.

Data transfers using the BITS service can take place over HTTP, SSL, and SMB. When BITS uses HTTP traffic, there is a distinctive User-Agent string of `Microsoft BITS/7.5` (or 7.8 in later versions). Unfortunately, there are no distinguishing characteristics of BITS SSL and SMB network traffic. Therefore the presence of BITS network traffic is not necessarily suspicious, because it is present anywhere Windows machines are connected to the internet. Analysts still can use Corelight data to assess if the BITS traffic is legitimate by analyzing remote systems being used for BITS data transfers. Are they outside of CDNs or major software providers’ networks? Additionally, all BITS uploads should be investigated until proven benign, as this use case is especially rare among legitimate software vendors.

The code sample below is an `http` log showing what the BITS data looks like if it is over HTTP.

```
_path: http
uid: Ca9LrF3xl5kVCxe2K4
id.orig_h: 10.10.199.31
id.orig_p: 49987
id.resp_h: 151.205.0.135
id.resp_p: 80
trans_depth: 1
method: GET
host: 151.205.0.135
uri: /pdata/0731497c8fa1dce5/download.windowsupdate.com/d/msdownload/update/software/secu/2018/05/windows10.0-kb4103723-x64_0722ab30824410046f954417ada8556d2ac308a6.cab
version: 1.1
user_agent: Microsoft BITS/7.8
request_body_len: 0
response_body_len: 1333068983
status_code: 200
status_msg: OK
resp_fuids: FD283F3hrZH8yzYmb8
resp_filenames: windows10.0-kb4103723-x64_0722ab30824410046f954417ada8556d2ac308a6.cab
resp_mime_types: [“application/vnd.ms-cab-compressed”]
accept_encoding: identity
accept: */*
```

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Microsoft BITS Leaving the Network|[./T1197-microsoft-bits-traffic-leaving-the-network.yml](./T1197-microsoft-bits-traffic-leaving-the-network.yml)|
