### Network Service Scanning [\[T1046\]](https://attack.mitre.org/techniques/T1046/)

To determine which devices on a network are exploitable, and the services available on those devices, an intruder can employ active scanning. Active scanning methods include:
- Horizontal scanning: Sending connection requests to a specific port across many IPs to see which IPs respond. For example, scanning across many devices on port TCP/22 typically reveals devices running an SSH server. Scanning across many devices on port TCP/445 can effectively enumerate Windows infrastructure.
- Vertical scanning: Sending connection requests to a single IP address across many ports to see which ports respond. This method lets attackers infer services available from that IP address.

Each of these methods can be performed using a free or commercially-available vulnerability scanner. These products often add other logic to check service availability, version information, and if services are vulnerable to known exploitation techniques.

If an intruder uses one or more of the above methods to attempt service discovery, the byproduct is a _failed_ or _rejected_ connection. In Corelight data, these are recorded in the `conn` log as connections with a `conn_state` of `S0` (initiated, and ignored) or `REJ` (initiated, and rejected), and typically have a history field where there is no `D` (post-syn data from the initiator). To look for network service scanning internal to the network:
1. Search for entries in the `conn` log where `conn_state` is `S0` or `REJ`.
2. Filter for records where `local_orig` is `true` and `local_resp` is `true`.
3. Group and count the results by the `id.orig_h`, and the number of unique `id.resp_p`, to assess the horizontal/verticalness of the scan.
4. Inspect the list, starting with the records that have the highest count of `id.resp_h` or `id.resp_p`.
5. Identify the originator (`id.orig_h`) and review the list of responders (`id.resp_h`) and ports (`id.resp_p`).
6. Determine whether the behavior is acceptable based on the identity of the source, the ports involved, and the destinations.

Not all items on the list are malicious. DHCP servers, for example, are commonly configured to ping an IP address to confirm if the address is in use before assigning it from the pool. Print servers with a large number of print queues attempt SNMP and/or network printing services to printers, even if those printers are offline. For this reason, print servers can cause large numbers of `S0` connections. Of course, software that scans legitimately, such as a corporate-sanctioned vulnerability scanner or an inventory management system, might appear in the list. Finally, network engineers conduct ad-hoc network scanning for troubleshooting purposes. If you run across network scanning, modify the original query to omit the records that are known to be benign, then resume hunting.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Network Service Scanning Multiple IPs for Open Port|https://tdm.socprime.com/tdm/info/WGq767q7rEuP |
|Network Service Scanning Multiple IPs|https://tdm.socprime.com/tdm/info/ezl5fGVY63MZ |
