import "pe"

rule MAL_Compromised_Cert_FakeBat_Certum_22B49BC752F530388C00E5A68FA4A344 {
   meta:
      description         = "Detects FakeBat with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-22"
      version             = "1.0"

      hash                = "e3ad2367d6e1e15a2f937310c4fa798fc33ef3300dd1c4c00785d914fb5bfb80"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Hangzhou Laisi Intelligent Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:b4:9b:c7:52:f5:30:38:8c:00:e5:a6:8f:a4:a3:44"
      cert_thumbprint     = "B7962BCBF0953078C35FD5D811CF255018EB26BF"
      cert_valid_from     = "2024-04-22"
      cert_valid_to       = "2025-04-22"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "91330108MA2B16Q83M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:b4:9b:c7:52:f5:30:38:8c:00:e5:a6:8f:a4:a3:44"
      )
}
