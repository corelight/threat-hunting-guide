![Corelight Logo](../images/logo-corelight.png)

# Introduction

This Threat Hunting Guide was created to teach you simple and relevant ways to discover attacks before they happen with Corelight network data. This document &mdash organized around the MITRE ATT&CK® framework &mdash is designed to help you develop a theory for threat hunting and establish prioritization.

About MITRE ATT&CK: MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It’s used as a foundation for specific threat models and methodologies in the private sector, government, and the cybersecurity industry. With the creation of ATT&CK, MITRE is fulfilling its mission to solve problems for a safer world — by bringing communities together to develop more effective cybersecurity. ATT&CK is open and available to any person or organization for use at no charge.[^1]

[^1]: https://attack.mitre.org/

## What is threat hunting?

At a high level, threat hunting is actively looking for adversaries in your network _when you don’t know if they’re inside_. This is different from indicator matching, which is only watching for well-known signs of attackers, for example, IP address(es) or file hash. Usually conducting a threat hunt involves researching a theory, or hunch, and then analyzing data looking for something _interesting_. Items that are _interesting_ can take many shapes, for example in _The Cuckoo’s Egg_, by Clifford Stoll an accounting error initiated the hunt.

> Dave wandered into my office, mumbling about a hiccup in the Unix accounting system. Someone must have used a few seconds of computing time without paying for it. The computer’s books didn’t quite balance; last month’s bills of $2,387 showed a 75-cent shortfall.

This 75-cent difference was the indicator that led to the discovery of multiple corporations and government systems that were compromised. The term "interesting" is used throughout this guide and it is only limited by your imagination.

## Why conduct a threat hunt?

Most host-or network-based detection systems rely on matching, otherwise known as signatures, to generate alerts to  signal defenders that there is something unwanted in the network. However, attackers are continually evolving to evade detection, and signatures are developed only after the artifact was discovered in another network. So, if you’re not hunting for artifacts in your environment, how will you discover that attackers are evading your current defenses?

Hunting has several positive outcomes. The first is you might find artifacts of an active intruder that your current defenses missed. While some may think this is a tragedy, it can be a huge win, especially if the intruder hasn’t completed their objective(s). In every hunt there’s always _something_ to find.

You may discover network or software misconfigurations that pose a threat, either because they degrade network performance or introduce a vulnerability. Next, the hunt could yield run-of-the-mill infections such as adware, or  other dormant malware that aren’t directly targeting your organization &mdash but are still a threat. Lastly, resource abuse and Shadow IT, services that are not officially supported, can introduce risk through degraded network performance or new adversary attack vectors. Every hunt teaches you something new about the network which will aid in your next investigation.

## Why hunt with network data?

Packets. Don’t. Lie.

It’s really as simple as that. If a network-resident intruder is active in your network, there will be network artifacts.  In artifacts, there are clues to what is happening, or better yet, an exact moment-for-moment story of what happened. For example, if a command and control channel uses DNS as a transport mechanism, there will be DNS queries and replies. Additionally, the IP address(es) that are on the ends of a TCP connection must be accurate, they cannot be spoofed if data is exchanged. All attacks traverse the network, unless they are isolated to one host, so there will be packets.

## Corelight logs nomenclature

Corelight provides data-centric solutions that analyze network traffic and enhance automation tools by transforming network traffic into linked logs and extracting files. The central log is the `conn` log, which documents general information about all network sessions.

The `conn` log records information about each network endpoint and the service (application) and also assigns a `uid` (unique identifier). The `uid` links the `conn` log to related protocol logs, where specific session information is available. For example, the `conn` log can list `http` as the `service`, and using the `uid` you can pivot to the `http` log to get specific protocol information about the session. The `uid` separates Corelight solutions from other security tools.  This field links otherwise disparate information into easily digestible logs. The `uid` is fundamental to conducting link analysis and a critically important field that facilities pivoting, or joining multiple logs together.

![Example of UID linkage](../images/uid-pivot-example-1.png)

The information about each network endpoint is summarized by the `id` field, which is usually represented as four separate fields:

- `id.orig_h`
- `id.orig_p`
- `id.resp_h`
- `id.resp_p`

This nomenclature may seem odd to use, because networking personnel traditionally refer to sessions using client and server; however, using `orig` (originator) and `resp` (responder) allows security personnel to accurately describe the connection.   Think of the originating host (`orig_h`)  as the source, or client, and the responding host (`resp_h`) as the destination, or server. The fields `id.orig_p` and `id.resp_p` will be populated with the corresponding port numbers.

Many of the remaining fields within the `conn` log and other protocol logs are self-descriptive, but if you get stuck, look at the Zeek documentation at https://docs.zeek.org/en/current/ for more detailed information or visit the Zeek community Slack channel.

## Identifying users and devices

When identifying devices on a network the IP or MAC addresses are regularly used to create the ‘identity’. The device IP address is used more often for the remote identity of a device because it survives router boundaries. When inside a network segment, the MAC address is preferred for identification because it can be a reliable identifier of a specific machine. Each identifier has pros and cons, and the ability of Corelight to capture both aids SOC personnel as they investigate events.

While IP addresses are durable[^2] for internal investigations, they often are transient within a network due to most networks implementing DHCP (Dynamic Host Configuration Protocol). Transient IPs are problematic for defenders when the IDS alert identifies the session by  IP addresses. Those IP addresses are only related to the alert _at the time that the alert was generated_.

[^2]: When used as an intel indicator an external IP, it is considered brittle, due to the ease with which adversaries can move to a new host or provider.

You can use open source tools when conducting an investigation (for example, `nslookup`), to provide DNS information for remote IPs. However, this is a point-in-time piece of information _at the time of the investigation, not when the event occurred_. A better technique is to use logs created at the time of the alert to capture the IP and FQDN for the remote device. To locate them internally, you can mine DHCP logs to identify the local device. There are multiple ways to identify a host and Corelight provides this data in multiple logs that each tell a different aspect of the story. Exercise creativity and follow every lead.

Where hostnames can be found:
- **`dhcp.log`**: `host_name` and `domain` fields represent the hostname and domain reported by a host when requesting an IP address via DHCP, and the `assigned_addr` field is the IP address that was assigned to that host.
- **`dns.log`**: if there’s an IP in the `answers` field, then the `query` field contains the hostname that the DNS server recorded (at that time) for the IP address.
- **`ntlm.log`**: `server_dns_computer_name` and `server_nb_computer_name` refer to the DNS and Netbios names of the machine with the IP address in the `id.resp_h` field. The `hostname` field is the hostname of the machine with the IP address in the `id.orig_h` field.
- **`kerberos.log`**: in a Windows environment, for domain-joined devices, Kerberos requests where the `client` field contains a name ending in `$`, the `client` field is the hostname, and the `id.orig_h` field is the IP address of that host. The `client` field is often structured like `HOSTNAME$/EXAMPLEDOMAIN.COM` where `HOSTNAME` is the hostname and `EXAMPLEDOMAIN.COM` is the Windows domain name and Kerberos realm name.
- **`http.log`**: the `host` field contains the hostname, domain name, or IP address of the client that requested data from the HTTP server. Sometimes this field is an indication of the identity of the server, the device with the IP address in the `id.resp_h` field.
- **`ssl.log`**: `server_name` field is extracted from the Server Name Indication (SNI) field in the TLS/SSL negotiation, and is used similarly to the `host` field of the `http` log. Also, the `subject` field is extracted from the subject of the server certificate, and the canonical name (CN) portion of the `subject` can provide clues to identify a server.

When identifying users, there are several logs that provide valuable information:

- **`rdp.log`**: depending on the version of the RDP protocol, the value of the `cookie` field is the username asserted by the client, and the client IP is in the `id.orig_h` field.[^3]
- **`ftp.log`**: the `user` field contains the username asserted by the client, and the client IP address will be in the `id.orig_h` field.
- **`irc.log`**: the `user` field contains the username asserted by the client, and the client IP address will be in the `id.orig_h` field.
- **`socks.log`**: the `user` field contains the username asserted by the client, and the client IP address will be in the `id.orig_h` field.
- **`http.log`**: the `username` field contains the username asserted by the client, and the client IP address will be in the `id.orig_h` field, or may be indicated in the `proxied` field if the connection was proxied. If proxied, the `id.orig_h` field will contain the IP address of the proxy.
- **`ntlm.log`**: the `username` field contains the username asserted by the client, and the client IP address will be in the `id.orig_h` field.
- **`kerberos.log`**: in a Windows environment, Kerberos requests contain the username in the `client` field (except for requests where the client field contains a name ending in `$`, which means that the asserting identity is a device, and the `id.orig_h` field is the IP address of the source device. The `client` field will often be structured like `USERNAME/EXAMPLEDOMAIN.COM` where `USERNAME` is the username and `EXAMPLEDOMAIN.COM` is the Windows domain name and Kerberos realm name.

[^3]: Not all versions of RDP assert the username in the `cookie` field. Some just assert nothing, or gibberish. In those instances, you would have to infer it from the NTLM or Kerberos log.

A few words of warning about drawing conclusions about the identity of a machine or the user of a device: know your limits (and the limits of the data). Just because a username was recorded in network traffic does not mean that the actual person with that name is responsible — it is just a clue. You should check to see if the user authenticated successfully, as state-sponsored cyberspies and saboteurs have increasingly experimented with planting false flags[^4]. The username could have been _asserted_, but if the authentication failed, then it is not a clear indicator that the user was involved. Don’t forget that devices and software may cache credentials, so the user account may be active, but the actual person could still be innocent. You must continue to collect information before you can confirm nefarious behavior.

[^4]: https://www.wired.com/story/untold-story-2018-olympics-destroyer-cyberattack/

For example:

- A user goes to lunch and leaves their device unlocked. Another user has walked up and is now using the device.
- A device is compromised with a Remote Access Trojan (RAT) and a user halfway around the world is surreptitiously assuming the identity of our victim,  while the original user is also using the device simultaneously to conduct regular business.
- A malicious user within the organization has overheard a coworker saying their password out loud in conversation, and he or she is now trying to use those credentials to log in to other systems.

Also, make sure you understand what pieces of information are controlled and asserted by the clients or servers, and consider who controls each. If an adversary is inside your network, determining what information is trustworthy is paramount when preparing the response plan. For example, an intruder could disable DHCP and statically assign an IP address and use it to navigate the network making identification difficult, as the DHCP server records would provide conflicting information (or none at all). Additionally, when a client requests a DHCP address, an intruder could provide a false MAC address. Thus the importance of capturing passive point-in-time logs when the event occurred.
