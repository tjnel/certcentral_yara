import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005A844DE10AEE66D4A060700000005A844 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-07"
      version             = "1.0"

      hash                = "39f9674b361e83875a551bd09a49d0cc152c7fcb70f3a62970cf13a4871b97b6"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:a8:44:de:10:ae:e6:6d:4a:06:07:00:00:00:05:a8:44"
      cert_thumbprint     = "392794012DAF0A5BA34BD91426BA274860FE19A8"
      cert_valid_from     = "2025-12-07"
      cert_valid_to       = "2025-12-10"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:a8:44:de:10:ae:e6:6d:4a:06:07:00:00:00:05:a8:44"
      )
}
