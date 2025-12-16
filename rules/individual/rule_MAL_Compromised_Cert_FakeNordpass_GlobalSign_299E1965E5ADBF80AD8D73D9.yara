import "pe"

rule MAL_Compromised_Cert_FakeNordpass_GlobalSign_299E1965E5ADBF80AD8D73D9 {
   meta:
      description         = "Detects FakeNordpass with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-23"
      version             = "1.0"

      hash                = "23ab0bc5d42e1311a672c4b3a4cf1ea8acd673efad132857fee254fdc80d32e6"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Razvitie LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "29:9e:19:65:e5:ad:bf:80:ad:8d:73:d9"
      cert_thumbprint     = "EE219612AB96F1A19CCED0D8897567276493D84D"
      cert_valid_from     = "2025-04-23"
      cert_valid_to       = "2026-04-24"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1157847087012"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "29:9e:19:65:e5:ad:bf:80:ad:8d:73:d9"
      )
}
