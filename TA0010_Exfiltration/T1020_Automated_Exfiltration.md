### Automated Exfiltration [\[T1020\]](https://attack.mitre.org/techniques/T1020/)

If an attacker is using an automated means of exfiltration, data artifacts are captured in the Corelight data.

To look for exfiltration in your network, you can use the Zeek package developed to calculate Producer/Consumer Ratio (PCR). PCR values indicate whether flows are consumptive (download) versus productive (upload). PCR values range from -1 (consumptive) to +1 (productive). To hunt for exfiltration using this package:

1. Install and enable the PCR package.
2. Generate a table of `id.orig_h`, `id.resp_h`, `id.resp_p`, and `pcr` from the `conn` log.
3. Use `local_orig` is `false` or `local_resp` is `true` to filter the results.
4. Reduce the results by filtering where `pcr` <= `0`.
5. For each host generating flows where `pcr` >= `0`, consider whether that host is expected to transmit data, inside or outside the network.

Another option is to use a SIEM to calculate the PCR using the information available in the Corelight conn log. The following Splunk query creates a table organized by host that contains the originating and responding bytes and a PCR value.

```
index=corelight sourcetype=corelight_conn | stats sum(orig_bytes) as Total_orig_bytes, sum(resp_bytes) as Total_resp_bytes by id.orig_h id.resp_h | eval PCR=(Total_orig_bytes-Total_resp_bytes)/(Total_orig_bytes+Total_resp_bytes) | fields id.orig_h id.resp_h Total_orig_bytes Total_resp_bytes PCR
```
