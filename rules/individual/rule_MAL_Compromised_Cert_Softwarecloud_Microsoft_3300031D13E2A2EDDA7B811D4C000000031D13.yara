import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300031D13E2A2EDDA7B811D4C000000031D13 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "6d0a738e24d53927a2070930222aaedec619f3ef22691d2fc37253a7163a45c7"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:1d:13:e2:a2:ed:da:7b:81:1d:4c:00:00:00:03:1d:13"
      cert_thumbprint     = "63EDBFA95EFBC778D67408868A356AEE46D5227A"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2025-06-08"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:1d:13:e2:a2:ed:da:7b:81:1d:4c:00:00:00:03:1d:13"
      )
}
