import "pe"

rule MAL_Compromised_Cert_ClearFake_Certum_672237253A9B7EF9D02D7D1CB27A3FF4 {
   meta:
      description         = "Detects ClearFake with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-03"
      version             = "1.0"

      hash                = "a0fdc1beb7acceddb9b04bc4cff54d644cc97f53dcfc6189052484d437f6af63"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Foshan Yongqiheng Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "67:22:37:25:3a:9b:7e:f9:d0:2d:7d:1c:b2:7a:3f:f4"
      cert_thumbprint     = "36A0F423C1FA48F172E4FECD06B8099F0EBBAEB8"
      cert_valid_from     = "2024-09-03"
      cert_valid_to       = "2025-09-03"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440605MA55WQT94L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "67:22:37:25:3a:9b:7e:f9:d0:2d:7d:1c:b2:7a:3f:f4"
      )
}
