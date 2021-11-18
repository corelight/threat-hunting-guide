### External Remote Services [\[T1189\]](https://attack.mitre.org/techniques/T1133)

External remote services are used by adversaries to connect to internal network resources.

Effective hunting for misuse of remote services takes two steps; discovery, and analysis.

First, you must discover what remote services are in use. Asset and service inventory information should be collected first, but it’s insufficient. Often, there is natural “drift” as IT teams make changes to infrastructure and struggle to keep asset documentation current. Empowered users make this more difficult by setting up assets and services without involving or informing IT, a process known as “shadow IT.”

Traditional remote services, for example: RDP, VNC (remote framebuffer), and SSH (secure shell) contain a server component and a client component.  If you have a remote service hosted in your environment, attackers can exploit it externally to compromise machines inside the network. To identify these services, look for `conn` log entries in which the `service` field contains `rfb`, `rdp`, or `ssh`, and where `local_orig` is false and `local_resp` is true, or where the originator IP (`id.orig_h`) is external and the responder IP (`id.resp_h`) is on the organization network. Make note of any RFP/VNC, RDP, or SSH servers that are accepting connections from the internet.

Some remote services work in reverse, where an agent is installed on the local device, and it reaches _outward_ from inside the network to a set of external servers, for example, GoToMyPC and TeamViewer. This configuration is designed to to assist users (primarily home users) who don’t control the NAT or the firewall or aren’t sophisticated enough to be able to manage port forwarding or firewall rule management.

To discover if these remote services are in use in your environment, look for signs of outbound connections to the services. For example, TeamViewer uses TCP port 5938 to communicate with TeamViewer servers, so simply review the `conn` logs for connections where the `id.resp_p` is `5938` and `local_orig` is true and `local_resp` is false. TeamViewer also uses SSL, and the domain name of the connections should be `*.teamviewer.com`, so additionally you can look for entries in the `ssl` log in which the `server_name` contains, or better yet ends with, `teamviewer.com`. (Note: because this session works in reverse, the `id.orig_h`, is the device in your network that has the TeamViewer client installed.) Our second example, GoToMyPC attempts to contact `poll.gotomypc.com`. Examine the `http` log host field for `poll.gotomypc.com`, or entries in the `ssl` log in which the `server_name` is `poll.gotomypc.com`. For each client software package, the list of ports and domain names varies.

Now that we’ve discussed discovery of remote services, you should compare Corelight data to a list of all remote services that the IT department offers, such as:
- RDP Gateways
- VDI (Virtual Desktop Infrastructure) Gateways
- VPN (Virtual Private Network) Gateways
- SSH Servers

For each service exposed to the internet, get a list of connections to that service from the conn log, and include:
- `id.orig_h` - Origin IP address (client)
- `id.resp_h` - Responder IP address (server)
- `id.resp_p` - Responder port
- `service` - the application protocol that Zeek detected
- `history` - the history of the connection, e.g. what types of TCP flags were seen
- `orig_cc` - The originator’s country code

When filtering logs, ensure the history field starts with `Sh`. For TCP connections this means that the originator sent a SYN, and the responder replied with a SYNACK (handshake). This check eliminates connections where the server is not listening, or there is a firewall blocking the connection.

After you have gathered all the data, begin sifting through the logs for anything interesting, such as a connection from a country that is not expected. Use the `UID` from the `conn` log to follow-up with the application-specific Zeek logs (`rdp`, `rfb`, `ssh`). For example, the `rdp` log contains more details about the connection, such as the `cookie` field that can contain the username of the authenticating user. The last step is to check with the user to determine whether they were actively using the system at that time.

Corelight customers have access to the Encrypted Traffic Collection (ETC) that generates inferences, or insights, about encrypted traffic. The `ssh` log contains interesting information inferred about the SSH connection, such as:
- `KS` for connections that appear to contain client keystrokes
- `FU` and `FD` for connections which appear to contain a file upload or download, respectively
- `ABP` for connections which appear not to contain any authentication, but still are successful (“authentication bypass”)
- `SV` or `SC` for clients that appear to be version or capability scanning, respectively

If you’d like to learn more about the Corelight ETC, please contact our sales team at (510) 281-0760.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|RDP Scanning Potential Brute Force Common User Names|https://tdm.socprime.com/tdm/info/c7xY1roWE2IC |
|Response from External Facing Service (Overview Query)|https://tdm.socprime.com/tdm/info/0DXnfAfjvHGb |
|External Facing Service Using RFC 1918 Subnets|https://tdm.socprime.com/tdm/info/reE3a4YkWm3Z |
|External Facing ICS Modbus|https://tdm.socprime.com/tdm/info/485HfRqE1bAz |
|External Facing ICS DNP3|https://tdm.socprime.com/tdm/info/8E9slTATr6F5 |
|Uncommon External Facing Application Service|https://tdm.socprime.com/tdm/info/JJwtAfOIy2rv |
|Inbound RDP from Internet|[./T1133-inbound-rdp-from-internet.yml](./T1133-inbound-rdp-from-internet.yml)|
