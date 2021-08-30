### Fallback Channels [\[T1008\]](https://attack.mitre.org/techniques/T1008/)

Adversaries have been known to split communications between different protocols, using one for inbound C2 and another for outbound data. This allows for the communication to bypass firewall restrictions.

Malware that splits communication between two hosts for instructions and for exfiltration introduces a new challenge for defenders. Recognizing the linkage between suspicious control traffic and large data transfers is challenging, but Zeek provides packages and frameworks that synthesize data. For example, there is a package for determining the producer-consumer ratio for connections that  identifies imbalanced, and possibly suspicious, data transfers. Additionally, the Intelligence Framework enables coordination with other defenders by identifying  possible indicators of compromise (IP addresses, email addresses, and domain names) in Corelight data.

It’s difficult to correlate attackers using different communication methods and channels but Corelight content, along with Zeek frameworks and packages can help. They allow defenders to identify the hidden channels discreetly, providing multiple opportunities for detection.

Beyond watching for the previously mentioned C2 communication mechanisms, here are some other signs available in Corelight data:
- Use the `conn` log to identify communication patterns that indicate additional channels. (for example, using `id.orig_h` and `id.resp_h` to narrow connections to a time window and observe connections between the hosts that include odd ports, failed or refused connections, or interesting/suspicious elements).
- Use Corelight (ETC), or self-developed content, in conjunction with connection log discovery to find potential relationships between overlapping, adjacent, or interesting connections.
- Search for sequences of connections to unrelated hosts using different protocols or events in the `dpd` and `weird` logs as described in _Command and Control: Non-Standard Port_.
