import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_33000557226B80125970AC5C13000000055722 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-16"
      version             = "1.0"

      hash                = "a0e687868361593a50b09f28cb8be4c61d00aa6335d321188399adf38b4e1b28"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Armstrong Systems & Consulting Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:57:22:6b:80:12:59:70:ac:5c:13:00:00:00:05:57:22"
      cert_thumbprint     = "9301B51421F536EAA703FDA3B5040BF21EAE6EB1"
      cert_valid_from     = "2025-09-16"
      cert_valid_to       = "2025-09-19"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:57:22:6b:80:12:59:70:ac:5c:13:00:00:00:05:57:22"
      )
}
