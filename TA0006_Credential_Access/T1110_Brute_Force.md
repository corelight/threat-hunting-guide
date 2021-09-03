### Brute Force [\[T1110\]](https://attack.mitre.org/techniques/T1110/)

An adversary attempts to gain unauthorized access by systematically guessing a user’s password using a repetitive or iterative mechanism. Sometimes a brute force attack originates from a list of known information, increasing the likelihood of success.

For example, an attacker attempting to guess the password of an Active Directory account likely results in many connections to a Domain Controller on the LDAP port (389 or 636). An attacker attempting to discover API URLs in an e-commerce system generates many more connections to the web server than other clients in a similar time period and creates more HTTP status codes in the  400 and 500 range (errors) compared to other clients.

To look for a brute force attack:
1. In the `conn` log, aggregate by `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, and (optionally) `service`.
2. Add a count for the number of operations and sort by the highest counts.
3. Choose a time period that makes sense, based on the size of the network/data set, starting small and gradually increasing.
4. Filter records that are obviously permissible, such as repeated contacts from network or application performance monitoring systems, vulnerability management systems, or business applications.
5. For unknown or suspicious records, perform a deeper investigation on that behavior. For example, look for other connections originating from the remote IP address.
6. For protocols that can maintain connections over multiple transactions or attempts, look for long-standing connections. These long-standing connections can also indicate repetitive behavior.

Corelight Sensors include a script that logs connections that are maintained for longer than a set of thresholds, starting at ten minutes and continuing up to three days. If you are not a Corelight customer, but use open source Zeek, this script is available through the Corelight GitHub page.

To hunt for long connections with the Long Connections package installed:
1. Examine the `notice` log.
2. Review the entries where the `note` is `LongConnection::found`
3. Review each set of `id.orig_h`, `id.resp_h`, `id.resp_p` to understand whether these devices should have long connections.

To hunt for long connections without the Long Connections package installed:
1. Examine the `conn` log.
2. Gather a list of all connections with the following fields for each: `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `service`, and `duration` fields. This only includes connections that completed, either properly or via timeout. Currently-open connections are not represented in the results.
3. Sort the results by `duration`, bringing the longest connections to the top.
4. Investigate each result to determine whether it’s legitimate or expected behavior.
5. Filter out expected behaviors and thoroughly investigate anything that seems suspicious.

Corelight also gives you the Encrypted Traffic Collection (ETC), which automatically looks for brute force password guessing attempts against SSH servers within a single connection.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Potential Forced External Outbound Kerberos|https://tdm.socprime.com/tdm/info/kQqryT7wHeDC |
|Possible Kerberos Brute Force Attempt|https://tdm.socprime.com/tdm/info/hprRVwll8xTF |
|Multiple SSH Brute Inferences from Single IP|https://tdm.socprime.com/tdm/info/UR5BX111eXrH |
