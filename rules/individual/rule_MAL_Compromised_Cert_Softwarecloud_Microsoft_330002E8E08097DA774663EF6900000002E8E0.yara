import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002E8E08097DA774663EF6900000002E8E0 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-17"
      version             = "1.0"

      hash                = "1dbfa2c095b27207fe912398f53f06a3f72b904b3f89bda93fe6e316da6414c5"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:02:e8:e0:80:97:da:77:46:63:ef:69:00:00:00:02:e8:e0"
      cert_thumbprint     = "A3A4B968B73B9554FAA235AE727B5A4A9CB243C3"
      cert_valid_from     = "2025-05-17"
      cert_valid_to       = "2025-05-20"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:02:e8:e0:80:97:da:77:46:63:ef:69:00:00:00:02:e8:e0"
      )
}
