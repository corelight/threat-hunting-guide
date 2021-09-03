### Network Share Discovery [\[T1135\]](https://attack.mitre.org/techniques/T1135/)

The most common network sharing protocol abused by attackers is SMB, the standard for Windows file sharing. SMB is supported by every modern operating system. High-value documents that store PII, trade secrets, network diagrams, and other sensitive data, typically live on SMB shares in enterprises of all sizes.

Scanning for and discovering shares on an SMB server is typically done using a DCE/RPC command on TCP port 445. Specifically, a connection to the `srvsvc` pipe — which shows up in the `dce_rpc` logs as an endpoint by the same name — is followed by a call to the `NetShareEnumAll` or `NetShareEnum` functions (called “operations” in the Zeek log). These function calls are used for legitimate file-sharing purposes, and taken alone they are insufficient indicators of malicious intent. However, in combination with other indicators of lateral movement, they illustrate how an attacker moved laterally within a network. Prime targets for further investigation are ones that generate a large number of DCE_RPC function calls across a large number of hosts in a short period.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Network Share Discovery|https://tdm.socprime.com/tdm/info/LQrOYbtius38 |
|Domain User Enumeration Network Recon 01|https://tdm.socprime.com/tdm/info/RRKEZSWRASea |
|Multiple Remote SMB Connections from single client|https://tdm.socprime.com/tdm/info/YyrDC9f1z06X |
