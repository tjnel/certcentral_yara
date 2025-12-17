import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330004419D7A2C680ABC8CCA3300000004419D {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-27"
      version             = "1.0"

      hash                = "6fb166efdc068e50b6cb3b18a23d71f21d334bf1e15818cf218677d6cc49fef0"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "SOFTWARE DESIGN SERVICES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:04:41:9d:7a:2c:68:0a:bc:8c:ca:33:00:00:00:04:41:9d"
      cert_thumbprint     = "2CD009049167DC70AAB8AD71B834ED60B9202ABB"
      cert_valid_from     = "2025-06-27"
      cert_valid_to       = "2025-06-30"

      country             = "US"
      state               = "New York"
      locality            = "Wallkill"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:04:41:9d:7a:2c:68:0a:bc:8c:ca:33:00:00:00:04:41:9d"
      )
}
