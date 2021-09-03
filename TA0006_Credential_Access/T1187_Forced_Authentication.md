### Forced Authentication [\[T1187\]](https://attack.mitre.org/techniques/T1187/)

Some protocols automatically authenticate when a user accesses a resource without first checking to see if the resource being accessed is trusted. For example, an attacker can embed a reference in a Microsoft Office document to a file that’s hosted on an attacker-controlled UNC path (`\\servername\sharename\path\to\file`). When the user opens the file, the machine attempts to access the resource. The attacker-controlled server then challenges the machine for authentication, and under most circumstances, the victim machine automatically provides cached credentials, usually in the form of an NTLM hash. The attacker can then attempt to use the credentials for unauthorized access, usually through reversing the hash to get the password, or re-using the hash in a pass-the-hash attack.

This method requires the attacker to control server infrastructure. As a result, the most likely attack vector is spearphishing. The attacker phishes a user on the network, and the victim machine then reaches out to the attacker-controlled server across the internet. To hunt for this behavior, look for authentication across the internet:

1. Look in the `ntlm` log for any signs of NTLM authentication in which the destination IP (`id.resp_h`) is on the external network.
2. Look for entries in the `conn` log in which the `service` field contains `smb` (and/or `ntlm`), and `local_resp` is `false`.

In LLMNR or NBT-NS poisoning, an attacker listens to local LLMNR or NBT-NS broadcasts asking for a particular resource by name. The attacker then responds to the querying client spoofing the actual resource. If the resource is one that usually requires authentication, then the attacker can challenge the client for authentication. When the client authenticates, usually with a password hash, the attacker uses the credentials to impersonate the client and access resources.

You can effectively hunt for these attacks with Corelight data, but the sensor needs to be inside of the broadcast domain because broadcast traffic doesn’t typically traverse routers. Typically you need to span or mirror entire VLANs, or forward LLMNR or NBT-NS traffic from client subnets and VLANs, to places on the network that Corelight is monitoring.

Look for `dns` logs where `id.resp_p` equals `5355` (LLMNR) or `id.resp_p` equals `137` (NBT-NS), and filter for records where the `answers` field is non-empty. Then count the number of distinct query fields per `id.resp_h`. This search yields IPs that respond to more than one name.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Potential Webdav Forced Authentication|https://tdm.socprime.com/tdm/info/5lg8sgL2BXFP |
|Potential Forced External Outbound NTLM|https://tdm.socprime.com/tdm/info/IGDdUPRsbbnt |
|Potential Forced External Outbound SMB|https://tdm.socprime.com/tdm/info/PQaoHNp76lqa |
|Potential Forced External Outbound Kerberos|https://tdm.socprime.com/tdm/info/kQqryT7wHeDC |
|Potential Forced External Outbound DCE_RPC|https://tdm.socprime.com/tdm/info/H1djFh6F67tX |
|Potential Forced External Outbound GSSAPI|https://tdm.socprime.com/tdm/info/CYmjSgQd1gO7 |
|Potential Forced LLMNR Lookup|https://tdm.socprime.com/tdm/info/qFvpktKW5h0l |
|Potential Forced Netbios DNS Lookup|https://tdm.socprime.com/tdm/info/0zIMWtFAk3B0 |
