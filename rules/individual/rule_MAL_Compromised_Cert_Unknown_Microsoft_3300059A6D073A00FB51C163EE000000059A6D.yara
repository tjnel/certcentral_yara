import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300059A6D073A00FB51C163EE000000059A6D {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-24"
      version             = "1.0"

      hash                = "23bb921bc74abf3efc73cbedb9c4524ae97657dea32531f9d31228573cb5a876"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Armstrong Systems & Consulting Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:9a:6d:07:3a:00:fb:51:c1:63:ee:00:00:00:05:9a:6d"
      cert_thumbprint     = "34B2C02EE1A6E5C936930503E43F67E9153F34FE"
      cert_valid_from     = "2025-09-24"
      cert_valid_to       = "2025-09-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:9a:6d:07:3a:00:fb:51:c1:63:ee:00:00:00:05:9a:6d"
      )
}
