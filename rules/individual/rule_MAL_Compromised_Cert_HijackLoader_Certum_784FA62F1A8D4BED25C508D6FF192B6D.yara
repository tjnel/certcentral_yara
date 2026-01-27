import "pe"

rule MAL_Compromised_Cert_HijackLoader_Certum_784FA62F1A8D4BED25C508D6FF192B6D {
   meta:
      description         = "Detects HijackLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "f7ac622a5d22df58331a0b10605fd7c408fdf3b28641522c5ccc117da69c4bc3"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = "Ref: https://app.any.run/tasks/835b2031-e64b-47df-be5a-12bc7150ea1a"

      signer              = "池州辰苼贸易有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "78:4f:a6:2f:1a:8d:4b:ed:25:c5:08:d6:ff:19:2b:6d"
      cert_thumbprint     = "34174E86794A12235BC628BA2D641A33D89CF5C0"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "CN"
      state               = "安徽"
      locality            = "池州"
      email               = "???"
      rdn_serial_number   = "91341700MAEC6EF50F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "78:4f:a6:2f:1a:8d:4b:ed:25:c5:08:d6:ff:19:2b:6d"
      )
}
