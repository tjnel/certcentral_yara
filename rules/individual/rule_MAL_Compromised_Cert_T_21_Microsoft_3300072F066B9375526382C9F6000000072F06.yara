import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300072F066B9375526382C9F6000000072F06 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "7bf13bc616fcc830b7ff20d505d1a1fb2e0fe0a5d8831d3ea8d9d19ca397e8ca"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex builds delivered from fake meeting websites impersonating companies worldwide"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:2f:06:6b:93:75:52:63:82:c9:f6:00:00:00:07:2f:06"
      cert_thumbprint     = "D2ECF3FA3F3279FDDCBE91B514B792D4C9890A88"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2026-01-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:2f:06:6b:93:75:52:63:82:c9:f6:00:00:00:07:2f:06"
      )
}
