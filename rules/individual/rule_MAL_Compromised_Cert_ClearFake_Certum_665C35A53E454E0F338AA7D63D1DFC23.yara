import "pe"

rule MAL_Compromised_Cert_ClearFake_Certum_665C35A53E454E0F338AA7D63D1DFC23 {
   meta:
      description         = "Detects ClearFake with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-22"
      version             = "1.0"

      hash                = "2da62d1841a6763f279c481e420047a108da21cd5e16eae31661e6fd5d1b25d7"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Fuzhou Xingmeng Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "66:5c:35:a5:3e:45:4e:0f:33:8a:a7:d6:3d:1d:fc:23"
      cert_thumbprint     = "3889079227EEDD36B4DD7604157D7F7186B5B741"
      cert_valid_from     = "2024-08-22"
      cert_valid_to       = "2025-08-22"

      country             = "CN"
      state               = "Fujian"
      locality            = "Fuzhou"
      email               = "???"
      rdn_serial_number   = "91350105MA353FCR11"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "66:5c:35:a5:3e:45:4e:0f:33:8a:a7:d6:3d:1d:fc:23"
      )
}
