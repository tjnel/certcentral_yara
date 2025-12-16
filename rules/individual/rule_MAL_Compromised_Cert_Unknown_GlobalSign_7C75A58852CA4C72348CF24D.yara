import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7C75A58852CA4C72348CF24D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-04"
      version             = "1.0"

      hash                = "3c3c8656d086505661895fbd4257802e44c2233b2d53e862c0b8320ea1a7fca5"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Bravery"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:75:a5:88:52:ca:4c:72:34:8c:f2:4d"
      cert_thumbprint     = "FB85AA1E12C09130035D3EB72B50EBF5CCE092C7"
      cert_valid_from     = "2025-07-04"
      cert_valid_to       = "2026-07-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1226100007077"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:75:a5:88:52:ca:4c:72:34:8c:f2:4d"
      )
}
