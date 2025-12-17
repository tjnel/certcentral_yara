import "pe"

rule MAL_Compromised_Cert_SearchLoader_Microsoft_3300066CC50AEC31F33A55EF36000000066CC5 {
   meta:
      description         = "Detects SearchLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-25"
      version             = "1.0"

      hash                = "98153ac06f5570ee6b94ed63c0eecda41b54e6e36a3a9f33ab466e5b2d421a4a"
      malware             = "SearchLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Linkus Corporation"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:6c:c5:0a:ec:31:f3:3a:55:ef:36:00:00:00:06:6c:c5"
      cert_thumbprint     = "4DFDE1C4FAABBEB26732FD3A967C8977BBCB8A36"
      cert_valid_from     = "2025-11-25"
      cert_valid_to       = "2025-11-28"

      country             = "US"
      state               = "Colorado"
      locality            = "Brighton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:6c:c5:0a:ec:31:f3:3a:55:ef:36:00:00:00:06:6c:c5"
      )
}
