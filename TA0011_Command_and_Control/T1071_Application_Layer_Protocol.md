### Application Layer Protocol [\[T1071\]](https://attack.mitre.org/techniques/T1071/)

Adversaries can abuse existing protocols for communication or command and control, usually because some protocols are allowed through existing network controls. There are a couple of generic ways to start looking for this:
1. Think about protocols that are allowed to pass the network boundary, either directly or through some sort of a relay
    1. DNS
    2. ICMP
    3. HTTP
2. Consider what "normal" characteristics would be for this traffic, then consider how to look for abnormal traffic

For example, DNS could be used to communicate out of the network because DNS is often allowed through firewall policies, and alternatively because DNS is largely proxied out of the environment through the use of recursive resolvers. If a command and control protocol used DNS and a domain generation algorithm (DGA) to find the command and control infrastructure, many non-existent domains would be looked up, resulting in many failures. This would show up in the `dns` log as a single client `id.orig_h` with many records where the `rcode_name` is `NXDOMAIN`.

Alternatively, information could be encoded in the DNS queries and responses using unicode. This would result in DNS records with non-ASCII characters in the query or response.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|C2 DGA Detected Via Repeative Failures|https://tdm.socprime.com/tdm/info/rWwyuT7y5GZF |
|DNS TXT With Non ASCII Character|https://tdm.socprime.com/tdm/info/WEFUMT3mbaAA |
