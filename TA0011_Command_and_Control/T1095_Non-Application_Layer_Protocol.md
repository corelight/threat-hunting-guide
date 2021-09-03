### Non-Application Layer Protocol [\[T1095\]](https://attack.mitre.org/techniques/T1095/)

Malware sometimes employs standardized lower-level protocols like ICMP, UDP, and SOCKS to avoid detection as these protocols are rarely monitored. For example, malware authors might embed C2 instructions in an ICMP Echo Request ("ping") packet.

Corelight monitors all connections regardless of protocol, and stores connection data within the `conn` log. C2 channels that employ custom UDP protocols or TCP-based SOCKS protocols (but no standard application layer protocols) have `conn` log entries with no identifiable `service` field. These fields and logs provide visibility into traffic flows across the network — even ICMP, UDP, and SOCKS. For ICMP sessions, Corelight data contains more than just the source and destination, for example; packet counts, bytes transferred, and size of ICMP data for both the sender and recipient.

With this data, you have the information needed to discover abnormally large or frequent ICMP communications that can be indicative of C2.  The following log is a sample of the `socks` log.

```
_path: socks
uid: C5u9ig4ACZvweN5my6
id.orig_h: 192.168.0.2
id.orig_p: 55951
id.resp_h: 192.168.0.1
id.resp_p: 1080
version: 5
user: bob
status: succeeded
request.host: 192.168.0.2
request_p: 22
bound.host: 192.168.0.1
bound_p: 55951
```

To hunt for an intruder using a standard non-application layer protocol to tunnel information:
1. Search the `conn` log for entries where the `service` field is blank, `local_orig` is `true`, and `local_resp` is `false`.
2. Aggregate those results by `id.orig_h`, `id.resp_h`, `id.resp_p` and summarize by count.
3. Filter to remove ‘normal’ entries.
4. Investigate any remaining items, focusing on the line items with the greatest count first.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|SSH Inference Abnormal Client Activity|https://tdm.socprime.com/tdm/info/DxYkDjI8pMBj |
|Custom Cryptographic inference determined by Corelight|https://tdm.socprime.com/tdm/info/0ds7shsorVkj |
