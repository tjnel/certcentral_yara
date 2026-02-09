import "pe"

rule MAL_Compromised_Cert_Donut_Certum_1732215D6B96071060E7551FFD98D6C7 {
   meta:
      description         = "Detects Donut with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "c901f1ea493e4d36d9c3ff7b1be05f62988e6613b8105dd6e238383b88c2303d"
      malware             = "Donut"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xi'an Weijian Yangyue Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "17:32:21:5d:6b:96:07:10:60:e7:55:1f:fd:98:d6:c7"
      cert_thumbprint     = "859EE087FDA779B9FAACA4CB7B63D51DA3DFB011"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "CN"
      state               = "Shaanxi"
      locality            = "Xi'an"
      email               = "???"
      rdn_serial_number   = "91610132MADG6C6Q1G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "17:32:21:5d:6b:96:07:10:60:e7:55:1f:fd:98:d6:c7"
      )
}
