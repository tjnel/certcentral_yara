import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330005057672A0AAC2A4B79566000000050576 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-24"
      version             = "1.0"

      hash                = "717c2728b957a7faecb7d1ac057bb03053f6397bbc369092c493daf6d45dc67c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:05:76:72:a0:aa:c2:a4:b7:95:66:00:00:00:05:05:76"
      cert_thumbprint     = "E3EFCCB48A282FE2091CBA889D79BF65DEF49607"
      cert_valid_from     = "2025-10-24"
      cert_valid_to       = "2025-10-27"

      country             = "US"
      state               = "New Hampshire"
      locality            = "Salem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:05:76:72:a0:aa:c2:a4:b7:95:66:00:00:00:05:05:76"
      )
}
