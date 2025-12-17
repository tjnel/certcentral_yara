import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_391BABE58A1109B9912B3596F8F8DC32 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-19"
      version             = "1.0"

      hash                = "5d1e3b113e15fc5fd4a08f41e553b8fd0eaace74b6dc034e0f6237c5e10aa737"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Songyuan Meiying Electronic Products Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "39:1b:ab:e5:8a:11:09:b9:91:2b:35:96:f8:f8:dc:32"
      cert_thumbprint     = "FB82D49AF0A77C3EF51873E9561445084BD7AE4A"
      cert_valid_from     = "2024-07-19"
      cert_valid_to       = "2025-07-19"

      country             = "CN"
      state               = "Jilin"
      locality            = "Songyuan"
      email               = "???"
      rdn_serial_number   = "91220700MA0Y47UL1G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "39:1b:ab:e5:8a:11:09:b9:91:2b:35:96:f8:f8:dc:32"
      )
}
