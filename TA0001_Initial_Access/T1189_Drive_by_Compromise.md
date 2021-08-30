### Drive-by Compromise [\[T1189\]](https://attack.mitre.org/techniques/T1189/)

A drive-by compromise usually results when a file is surreptitiously downloaded from a website that is compromised. When you hunt for signs of drive-by compromise in Corelight data, your main focus is downloads from external websites.

Begin the hunt with the `http` log and look for signs of downloaded executables:

1. Start with http logs where resp_fuids is not empty. This means there was a file returned from the responder.
2. If the data volume is too large, filter out local (in-network) responders.  You can filter by joining the results to the `conn` log on the `uid`, then filtering out any records in which `local_resp` is `true` in the `conn` log.
3. Review the `resp_mime_types` from the `http` log, and filter uninteresting results (for example, images, text, OCSP responses, and certificates). Often the most interesting results are executables, DLLs, and archives/containers
4. Group the results by the `host` and `resp_mime_types` fields for easy analysis.

Scan through the results and look for anything interesting or odd, such as downloads of executable files, or file extension and mime-type mismatch.

As more attackers move to using TLS to encrypt exchanges between compromised clients and websites they control, there will be less visibility via the `http` log. To regain this visibility, consider using an enterprise SSL decryption solution and passing the decrypted HTTP traffic to your Corelight sensor.

### Sigma Queries for Hunting

- [Query 1](https://sample.link/path)
