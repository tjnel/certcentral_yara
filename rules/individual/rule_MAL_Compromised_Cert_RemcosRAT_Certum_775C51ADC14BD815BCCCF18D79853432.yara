import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Certum_775C51ADC14BD815BCCCF18D79853432 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-17"
      version             = "1.0"

      hash                = "a681f4e8aff080bfbfeead57c1d44c7dc4165fe18fb72f3e22cea7b7e06a44f8"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Quanzhou Diancheng Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "77:5c:51:ad:c1:4b:d8:15:bc:cc:f1:8d:79:85:34:32"
      cert_thumbprint     = "D686B825DC006A20A55C03579B1AB0007E8372DF"
      cert_valid_from     = "2024-10-17"
      cert_valid_to       = "2025-10-17"

      country             = "CN"
      state               = "Fujian"
      locality            = "Quanzhou"
      email               = "???"
      rdn_serial_number   = "91350502315458956U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "77:5c:51:ad:c1:4b:d8:15:bc:cc:f1:8d:79:85:34:32"
      )
}
