### Web Service [\[T1102\]](https://attack.mitre.org/techniques/T1102/)

Web service is when attackers use a legitimate external web service to relay data to and/or from a compromised system.

Attackers sometimes use well-known web services for C2 channels to hide in the noise.  While this tactic makes identification more difficult, Corelight data — especially the `http`, `ssl`, `conn`, and `x509` logs — helps you identify suspicious connections. Looking for IOCs including URI, hostname, or specific certificate details (like SNI or CN) is a good place to start. The following provides a few examples of certificate fields that might warrant an investigation:

```
path: x509
id: FfUGTX1VqS1qR3OJm7
certificate.version: 3
certificate.serial: 00
certificate.subject: emailAddress=obama@us.com,O=Obama inc.,L=Gaza City,ST=Gaza Strip,C=12,
CN=http://usrep3.reimage.com
certificate.issuer: emailAddress=obama@us.com,O=Obama inc.,L=Gaza City,ST=Gaza Strip,C=12,CN=http://usrep3.reimage.com
certificate.not_valid_before: 2010-04-01T13:17:48.000000Z
certificate.not_valid_after: 2011-04-01T13:17:48.000000Z
certificate.key_alg: rsaEncryption
certificate.sig_alg: sha1WithRSAEncryption
certificate.key_type: rsa
certificate.key_length: 1024
certificate.exponent: 65537
```

#### Sigma Queries for Hunting
|Name|URL|
|--|--|
|Potentially Interesting user agent and mime type combination|https://tdm.socprime.com/tdm/info/FFnte4E6Qdte |
|Multiple Abnormal non conforming HTTP Requests|https://tdm.socprime.com/tdm/info/Ngrrev0hOYBC |
|HTTP Traffic with No HTTP Host Set or User Agent Set|https://tdm.socprime.com/tdm/info/opVUt7AJNj2w |
