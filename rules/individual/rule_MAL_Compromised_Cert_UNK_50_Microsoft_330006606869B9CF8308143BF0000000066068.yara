import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006606869B9CF8308143BF0000000066068 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "fa00db3864d8f5d471449f5df75c5006c054a474c1f62f7d9a3d6633c8d9bdf3"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:60:68:69:b9:cf:83:08:14:3b:f0:00:00:00:06:60:68"
      cert_thumbprint     = "ED7672988AA10F82D4B1E57B6FD0010FE829FBDB"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2025-12-07"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:60:68:69:b9:cf:83:08:14:3b:f0:00:00:00:06:60:68"
      )
}
