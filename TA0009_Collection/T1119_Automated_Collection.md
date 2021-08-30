### Automated Collection [\[T1119\]](https://attack.mitre.org/techniques/T1119/)

Attackers can deploy automated tools on a compromised host to monitor intranet services for sensitive data and corporate secrets. These tools can include scripts to search for (and copy) information such as file type, location, or name at specific time intervals. Intruders may use remote access tools to conduct automated collection.

For example, a custom tool may query an intranet web server or an internal email server, polling regularly for new content. Corelight monitors multiple protocols including HTTP, SMTP, MySQL, FTP, and SMB traffic to provide insight into these queries.

When hunting for automated collection use, defenders can identify automated tools by watching for repetitive queries or regularly scheduled connections. For example, if an intruder is web scraping, there will be a large number of connections from a finite number of IP addresses. Additionally, you can use the SMB logs (`smb_files` or `smb_mapping`) to identify anomalous traffic patterns.
