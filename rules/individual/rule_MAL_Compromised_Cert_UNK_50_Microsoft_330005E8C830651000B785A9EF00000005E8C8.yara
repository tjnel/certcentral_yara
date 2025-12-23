import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005E8C830651000B785A9EF00000005E8C8 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-21"
      version             = "1.0"

      hash                = "8da84cd59a5f9896c8309e706105b37eed6fbd78fa006b05237f2440dfeef03a"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTOLIO sp. z o.o."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:e8:c8:30:65:10:00:b7:85:a9:ef:00:00:00:05:e8:c8"
      cert_thumbprint     = "45A7460A9F8217E55A14FB5DC7187EF7A7BDDE32"
      cert_valid_from     = "2025-12-21"
      cert_valid_to       = "2025-12-24"

      country             = "PL"
      state               = "Pomorskie"
      locality            = "GDYNIA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:e8:c8:30:65:10:00:b7:85:a9:ef:00:00:00:05:e8:c8"
      )
}
