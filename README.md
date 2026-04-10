# Overview
A Go command line tool that does a lot of digging...find and print all common DNS records for the provided domain.

```
$ go run cli/main.go -i meantimecyber.com
Looking up domain: "meantimecyber.com"
Got 9 records for domain "meantimecyber.com":
Records for "meantimecyber.com"

A (IPv4 Address) Records
-----------------------------

┏━━━━━━━━━━━━━━━┓
┃ Address       ┃
┡━━━━━━━━━━━━━━━┩
│ 104.21.7.12   │
│ 172.67.155.92 │
└───────────────┘

AAAA (IPv6 Address) Records
-----------------------------

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Address                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 2606:4700:3034::ac43:9b5c │
│ 2606:4700:3031::6815:70c  │
└───────────────────────────┘

MX (Mail Exchange) Records
-----------------------------

┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Preference ┃ Email Server     ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ 0          │ mail.tutanota.de │
└────────────┴──────────────────┘

NS (Name Server) Records
-----------------------------

┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record ┃ Name server              ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1      │ amanda.ns.cloudflare.com │
│ 2      │ apollo.ns.cloudflare.com │
└────────┴──────────────────────────┘

TXT (Text) Records
-----------------------------

┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record ┃ Value                                     ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1      │ t-verify=51c9638e6f8c281bf37638bb06664f71 │
│ 2      │ v=spf1 include:spf.tutanota.de -all       │
└────────┴───────────────────────────────────────────┘

SPF Record
-----------------------------

Raw SPF record: "v=spf1 include:spf.tutanota.de -all"

┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Key     ┃ Field                   ┃ Value           ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ v       │ Version                 │ v=spf1          │
│ include │ Included Sending Domain │ spf.tutanota.de │
│ All     │ All other mechanisms    │ -all            │
└─────────┴─────────────────────────┴─────────────────┘

DMARC Record
-----------------------------

Raw DMARC record: "v=DMARC1; p=quarantine; adkim=s; aspf=s; fo=1; rua=mailto:4cabfe162db0473d8617fbb3bd2e8715@dmarc-reports.cloudflare.net;"

┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Key   ┃ Field                ┃ Value                                                                ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ v     │ Version              │ DMARC1                                                               │
│ p     │ Policy               │ quarantine                                                           │
│ adkim │ DKIM Alignment       │ s                                                                    │
│ aspf  │ SPF Alignment        │ s                                                                    │
│ fo    │ Failure Options      │ 1                                                                    │
│ rua   │ Aggregate Report URI │ mailto:4cabfe162db0473d8617fbb3bd2e8715@dmarc-reports.cloudflare.net │
└───────┴──────────────────────┴──────────────────────────────────────────────────────────────────────┘

MTA-STS Record
-----------------------------

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type           ┃ Record                ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ TXT Record     │ v=STSv1; id=20190723; │
│ Policy version │ STSv1                 │
│ Policy mode    │ enforce               │
│ Policy mx      │ mail.tutanota.de      │
│ Policy max_age │ 86400                 │
└────────────────┴───────────────────────┘

Fin.

```

# Building and Running
Just run `Make` to build a binary, or `go run cli\main.go` to just run it.