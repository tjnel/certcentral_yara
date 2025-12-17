import "pe"

rule MAL_Compromised_Cert_Vidar_Microsoft_3300058A3280579A5F80EC354D000000058A32 {
   meta:
      description         = "Detects Vidar with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-30"
      version             = "1.0"

      hash                = "0fa64636b0b9f82665759aedc9a553e0a9b1c377823a350775fc8fb1a82df995"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Linkus Corporation"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:8a:32:80:57:9a:5f:80:ec:35:4d:00:00:00:05:8a:32"
      cert_thumbprint     = "79F42327460B0E95B283395746C80DEA1317B939"
      cert_valid_from     = "2025-11-30"
      cert_valid_to       = "2025-12-03"

      country             = "US"
      state               = "Colorado"
      locality            = "Brighton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:8a:32:80:57:9a:5f:80:ec:35:4d:00:00:00:05:8a:32"
      )
}
