import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300031611E4BA9F20E932640D000000031611 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-02"
      version             = "1.0"

      hash                = "bc7f2575b0029107f170d24e21750dd1edc31b763bd0721d2b36a0b7c61dfc51"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:16:11:e4:ba:9f:20:e9:32:64:0d:00:00:00:03:16:11"
      cert_thumbprint     = "1CF1C847ECAEF7982EB5CB639AA96CB78B14ACF6"
      cert_valid_from     = "2025-06-02"
      cert_valid_to       = "2025-06-05"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:16:11:e4:ba:9f:20:e9:32:64:0d:00:00:00:03:16:11"
      )
}
