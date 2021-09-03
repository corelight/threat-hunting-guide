### Ingress Tool Transfer [\[T1105\]](https://attack.mitre.org/techniques/T1105/)

Intruders typically move files onto compromised systems &mdash both tools that can assist with further lateral movement, and/or sensitive files designed for exfiltration. Those files will typically move over an HTTP(S), SSH, or SMB connection.

For files moving over plaintext HTTP, details like the remote host name and the name and mime type of the file being transferred can be useful indicators; users should also consult the `files` log for the hashes of files being moved, as many popular attacker tools have known cryptographic hashes that make identifying them easy. In the case of HTTPS, defenders can use the IP address of the remote system, as well as the certificate details noted in the `ssl` log (i.e. organization name, FQDN of the remote host from the CN, etc.) to look for anomalous connections.

Intruders copy files from one endpoint to another as they move laterally among compromised assets. Traditionally, file copies to or from Unix/Linux systems occur over the SSH protocol using the `scp` command. For Windows systems, remote file uploads or downloads typically happen over SMB, but also may use SSH via PuTTY.

Corelight Sensors with the ETC SSH inferences package enabled extend the `ssh` log. The extension includes an `inferences` field that adds inferred characteristics about the SSH traffic. For example, if the session is being used to move files, or if it is interactive:
- LFU: Large File Upload
- LFD: Large File Download
- KS: Keystrokes

To begin hunting for interesting SSH sessions use the `inferences` field in the ETC SSH package:
1. Identify sessions where the `inferences` field contains `LFU`, `SFU`, `LFD`, or `SFD`
2. Determine whether file activity via SSH is legitimate and expected

Corelight Sensors are preloaded with the MITRE BZAR (Bro/Zeek ATT&CK-Based Analytics and Reporting) package. MITRE BZAR identifies MITRE ATT&CK techniques for remote file copy, namel files being copied to `C$` or `ADMIN$` shares. This package generates entries in the `notice` log, as depicted below:

```
path: notice
uid: CiAtaM363GcEbU63zk
id.orig_h: 192.168.38.104
id.orig_p: 65431
id.resp_h: 192.168.38.102
id.resp_p: 445
fuid: FSeaVF4qnjl8cT3HF8
file_mime_type: text/plain
file_desc: Windows\\Temp\\hbaVJpzdnG
proto: tcp
note: ATTACK::Lateral_Movement_Extracted_File
msg: Saved a copy of the file written to SMB admin file share
sub: 2020-10-23/6f24ac6ce591baf02acd64684f596d2db0ec97c0
src: 192.168.38.104
dst: 192.168.38.102
p: 445
```

Even if you do not enable the MITRE BZAR package on your Corelight Sensor, Corelight still logs SMB share access in the `smb_mapping` log and file access and modification in the `smb_files` log. The following logs illustrate the data contained in the Corelight family of SMB logs:

```
_path: smb_mapping
uid: CiAtaM363GcEbU63zk
id.orig_h: 192.168.38.104
id.orig_p: 65431
id.resp_h: 192.168.38.102
id.resp_p":445
path: \\\\192.168.38.102\\C$
share_type: DISK
```

```
_path: smb_files
uid: CiAtaM363GcEbU63zk
id.orig_h: 192.168.38.104
id.orig_p: 65431,
id.resp_h: 192.168.38.102
id.resp_p: 445,
action: SMB::FILE_OPEN
path: \\\\192.168.38.102\\C$
name: Windows\\Temp\\hbaVJpzdnG
size: 1894,
times.modified: 2019-12-31T10:28:02.800834Z
times.accessed: 2019-12-31T10:28:02.753959Z
times.created: 2019-12-31T10:28:02.566496Z
times.changed: 2019-12-31T10:28:02.800834Z"
```

To hunt for lateral movement:
1. Start by searching the `smb_files` log, and focus on the `id.orig_h`, `id.resp_h`, `path`, and `name` fields.
2. Filter records where `id.resp_h` is a known file server, which reduces the results to potentially interesting connections.
3. Review the `path` and `name` fields to identify which share the file was accessed from or written to, and determine if the behavior is suspicious.
4. For additional context about the remaining interesting records, you can pivot to the `files` log, using the `uid` to collect specific information about the file(s). For example, the MD5/SHA1/SHA256 hash(es) are automatically calculated and can be used to identify known malware in external systems, such as VirusTotal.
    1. There are also other fields and possibly logs available (for example, the `pe` log) that can be used to rule out uninteresting records.

#### Sigma Queries for Hunting

|Name|URL|
|--|--|
|Potentially Interesting user agent and mime type combination|https://tdm.socprime.com/tdm/info/6zq27idnfPdG |
|Executable from Webdav|https://tdm.socprime.com/tdm/info/K0s0t7hq8DVz |
