### Archive Collected Data [\[T1560\]](https://attack.mitre.org/techniques/T1560/)

To conceal data, attackers may consolidate data into compressed archive files, such as Zip, RAR, TAR, or CAB files. To hunt for this obfuscation technique, use the `files` log.

To search for compressed files:
1. Search the `files` log, retrieving the `tx_hosts`, `rx_hosts`, `mime_type`, `total_bytes`, and `source` fields.
2. Remove records with uninteresting `mime_types` from the results, for example:
  - `application/x-x509-*`
  - `application/ocsp*`
  - `image/*`
  - `audio/*`
  - `video/*`
  - `text/*`
  - `application/xml`
  - `application/chrome-ext`

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Multiple Compressed Files Transferred Outbound|https://tdm.socprime.com/tdm/info/uslXmM2xWmWw |
|Multiple Compressed Files Transferred over HTTP|https://tdm.socprime.com/tdm/info/rJDgVmuJJCA7 |
