import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_33000301441BA67643DD87EF5E000000030144 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "d207830298fda267c7ea01afe5b429453587729040f525875cdd36eb4e606dc7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TEAM PLAYER SOLUTION LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:01:44:1b:a6:76:43:dd:87:ef:5e:00:00:00:03:01:44"
      cert_thumbprint     = "E11D7DD64E2F8CFDFC60B5B7959EC6BCE0D42B9F"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2025-03-17"

      country             = "GB"
      state               = "???"
      locality            = "Huntingdon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:01:44:1b:a6:76:43:dd:87:ef:5e:00:00:00:03:01:44"
      )
}
