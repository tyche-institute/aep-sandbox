# Time-stamp tokens over SEAL.sha256

This directory holds 2 time-stamp tokens (RFC 3161) over the file `../SEAL.sha256`. A token
is a signed statement by a time-stamping service: a file with this SHA-256 existed at the
stated time. We sent each service the SHA-256 and nothing else.

SHA-256 of `../SEAL.sha256`:

```
8d213af4da148ed8779a9c4663a02e2b847f2748311cba08f973d33ab2fb7303
```

| Service | Token | Time in the token (UTC) | Serial number |
|:--|:--|:--|:--|
| FreeTSA (freetsa.org) | `seal-freetsa.tsr` | 2026-11-14 05:11:11 | 0x0A019721 |
| DigiCert (timestamp.digicert.com) | `seal-digicert.tsr` | 2026-11-14 05:11:11 | 0x220EF8DFD9925DE96D5B3C4E28ED05BD |

`seal.tsq` is the request that we sent to both services. `freetsa-cacert.pem` and
`freetsa-tsa.crt` are the certificates of FreeTSA, from freetsa.org. For a stricter check,
fetch them from freetsa.org yourself.

## Check them

You need OpenSSL. From this directory:

```sh
openssl ts -verify -data ../SEAL.sha256 -in seal-freetsa.tsr -CAfile freetsa-cacert.pem -untrusted freetsa-tsa.crt
openssl ts -verify -data ../SEAL.sha256 -in seal-digicert.tsr -CAfile /etc/ssl/certs/ca-certificates.crt
```

Each command must print `Verification: OK`. The first command may also print a warning that
`freetsa-tsa.crt` is not a CA (certificate authority) certificate. That is expected: it is the
signing certificate of the service, passed with `-untrusted`. The second command reads the
certificate store of your system. The path above is the one on Debian and Ubuntu; other
systems keep the store elsewhere.

To read the time in a token:

```sh
openssl ts -reply -in seal-freetsa.tsr -text
```

## What this shows

`SEAL.sha256` existed, with these exact bytes, on 14 November 2026 at 05:11:11 UTC
(Coordinated Universal Time). That is Friday 13 November at 21:11 Pacific time, the
evening before the IETF 127 Hackathon room opened.

It shows nothing about earlier times. It shows nothing about the 4 files that `SEAL.sha256`
lists, beyond their SHA-256.

Tyche Institute only uses these 2 services here. It issues no time-stamps.
