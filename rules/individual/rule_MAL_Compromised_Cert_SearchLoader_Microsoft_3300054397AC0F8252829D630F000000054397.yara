import "pe"

rule MAL_Compromised_Cert_SearchLoader_Microsoft_3300054397AC0F8252829D630F000000054397 {
   meta:
      description         = "Detects SearchLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-15"
      version             = "1.0"

      hash                = "d67d1628ff5ea924c25c8056446a8143e1171fab7e30dddb24aca3255dad8817"
      malware             = "SearchLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hamilton Vision and Eye Care, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:43:97:ac:0f:82:52:82:9d:63:0f:00:00:00:05:43:97"
      cert_thumbprint     = "6E6737BDAE88C4D9C2F245C38E6D1008BFB166F5"
      cert_valid_from     = "2025-11-15"
      cert_valid_to       = "2025-11-18"

      country             = "US"
      state               = "Alabama"
      locality            = "HAMILTON"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:43:97:ac:0f:82:52:82:9d:63:0f:00:00:00:05:43:97"
      )
}
