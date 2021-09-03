### Proxy [\[T1090\]](https://attack.mitre.org/techniques/T1090/)

While the use of proxies doesn't itself prove the presence of an intruder, intruders can use proxies to "launder" connections to obscure the communication from defenders. There are many methods to observe this, including traditional analysis of the underlying connection (signature, anomaly, behavioral) and statistical analysis of connection properties. Specifically identifying proxied connections is critical for beginning hunting or investigation.

If you see a value in the `proxied` field of Zeek’s `http` log, that means that an HTTP connection was proxied. The `http` log captures proxy details from the HTTP headers. Search for any records in the `http` log that have a non-empty `proxied` field.


- `host`: the domain name of the website
- `id.orig_h`: the IP address of the proxy or reverse proxy
- `id.resp_h`: the IP address of the web server
- `proxied`: identifies the proxy and the original IP address of the client

For example, a client at IP 219.90.98.8 initiated this HTTP request. The request was proxied via 172.16.1.30 to the web server at 172.16.2.95.

```
host: www.totallyfakedomain.com
id.orig_h: 172.16.1.30 //the proxy
id.orig_p: 53,828
id.resp_h: 172.16.2.95 //the web server
id.resp_p: 80
method: POST
post_body: dXNlcm5hbWU9cm9vdCZwYXNzd29yZD1tb25rZXk=
proxied: X-FORWARDED-FOR -> 219.90.98.8 //the “real” client
status_code: 200
status_msg: OK
uri: /xmlrpc.php
user_agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)
log: http
```

Using this example, identify the proxy and determine whether it’s internal or external. If it’s external, evaluate the session and gain context, using Corelight data to decide whether or not to block it. If the proxy is internal, determine whether it’s a legitimate piece of IT infrastructure, or if it is a rogue proxy set up to circumvent policy  — shadow IT.

Additionally, SOCKS is a commonly used proxy protocol that Corelight sensors natively parse. When SOCKS is encountered, a `socks` log is generated and records details on users and protocols. This information can be used to ensure that connections aren’t malicious and comply with policy. In the `socks` log, focus on these fields:

- `id.orig_h`: the client IP address
- `id.resp_h`: the proxy IP address
- `request`: the domain or IP the client is attempting to access
- `user`: if it is an authenticated connection, the user using the proxy

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|External Proxy Detected (Overview Query)|https://tdm.socprime.com/tdm/info/Sit0tkQSDkyH |
