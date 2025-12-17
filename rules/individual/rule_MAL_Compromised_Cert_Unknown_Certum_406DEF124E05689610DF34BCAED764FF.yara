import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_406DEF124E05689610DF34BCAED764FF {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "0a0b9338389aced675f5b68eddfb6766bc2feb1a4b2be4e7eb61ba9aa82c4d50"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Benqi Electronic Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "40:6d:ef:12:4e:05:68:96:10:df:34:bc:ae:d7:64:ff"
      cert_thumbprint     = "BC55D25FD749078676F56B23577FDE913BFD518C"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-17"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5FAKPY62"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "40:6d:ef:12:4e:05:68:96:10:df:34:bc:ae:d7:64:ff"
      )
}
