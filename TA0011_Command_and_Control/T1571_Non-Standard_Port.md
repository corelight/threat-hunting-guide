### Non-Standard Port [\[T1571\]](https://attack.mitre.org/techniques/T1571/)

Adversaries may use a commonly used port to avoid more detailed inspection.

Hunting for C2 channels over commonly used ports is difficult, but not impossible. To look for C2 channels, search for well-known ports that are being used with an uncommon service.

When hunting for C2 using commonly used ports:
1. Initially focus on the `service` field, and search the `conn` log for entries where the `service` field isn’t what you would expect for the standard port (the service field could be either a `-` or another service).
  1. Start with the most common protocols.
    - TCP:80 (HTTP) TCP:443 (HTTPS)
    - TCP:25 (SMTP)
    - TCP/UDP:53 (DNS)
2. Corelight’s Encrypted Traffic Collection contains a package titled Encryption Detection. Encryption Detection generates a notice when cleartext traffic is observed on usually encrypted ports. Observing `notices` for `Viz::UnencryptedService` highlights this behavior and helps you identify potentially malicious connections using common ports.

The Corelight Encrypted Traffic Collection package also has a feature that notifies you when a session uses instant encryption. The package looks for pre-shared keys or encrypted connections that begin without a traditional key negotiation. Observing `notices` for `Viz::CustomCrypto` highlights this behavior and helps you identify potentially malicious connections using common ports.

Additionally, you can use the Corelight `dpd` and `weird` logs to identify unexpected protocol behavior. These logs show debugging and parsing errors and identify out-of-specification usage of common ports and protocols — which might indicate malicious activity or covert use of known ports and protocols.

```
_path: dpd
uid: C5LNtk1n9NkT8m300j
id.orig_h: 192.168.0.54
id.orig_p: 52841
id.resp_h: 54.89.42.30
id.resp_p: 80
proto: tcp
analyzer: HTTP
failure_reason: not a http request line
```

Every connection made in an environment monitored by Corelight is recorded in the `conn` log. After building a list of regularly used ports (for example, 22/SSH, 25/SMTP, 80/HTTP, and 443/SSL), you can query the Corelight data to find connections to ports that aren’t on that list.

If you encounter connections that appear on other non-standard ports, examine the Layer 7 service that Corelight observes and records in the `conn` log `service` field. Cases without a recognized service are the most suspicious, particularly if large volumes of data are being transferred or connection lengths are long.

When you encounter well-known services on irregular ports, examine the details in the corresponding protocol log for additional clues. For example, in the `http` log, make note of the name of the remote host, the client’s `user_agent` string, and the `uri`. Together, they might all contain clues as to the software that’s generating the request on the uncommon port.

```
path: conn
uid: CrlIbI1BJ8Al8ryyX6
id.orig_h: 192.168.0.53
id.orig_p: 4388
id.resp_h: 46.108.156.146
id.resp_p: 22205
proto: tcp
service: http
duration: 0.0013911724090576172
orig_bytes: 412
resp_bytes: 377
conn_state: RSTO
local_orig: true
local_resp: false
history: ShADadfR
orig_pkts: 7
orig_ip_bytes: 700
resp_pkts: 5
resp_ip_bytes: 585
resp_cc: DE
```
