### Data Transfer Size Limits [\[T1030\]](https://attack.mitre.org/techniques/T1030/)

An attacker may attempt to transfer data or files by “chunking” them into smaller pieces, to avoid hard-coded data transfer limits or thresholds. We will present two methods to hunt for this technique.

The first method analyzes data leaving the network based on source and destination pairs and requires a data aggregation/visualization platform(unless you enjoy AWKing and GREPing through data):
1. Generate a table from the `conn` log including the `id.orig_h`, `id.resp_h`, `id.resp_p`, and `sum(orig_bytes)`.
2. Sort the results by the largest `sum(orig_bytes)`.
3. Examine each host and determine if there is a legitimate reason for uploads to that destination.

The second method analyzes the frequency, and sizes, of outbound transfers from each source:
1. Generate a table from the `conn` log including `id.orig_h`, `id.resp_h`, `id.resp_p`, and `count(orig_bytes)`.
2. Sort the results by the largest `count(orig_bytes)`.
3. Examine the results and determine the reason for all the connections with the same amount of data flowing from the source to the destination.
