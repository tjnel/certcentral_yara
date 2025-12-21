import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Certum_418A597765E84F03F07933EFA3CC39D4 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-11"
      version             = "1.0"

      hash                = "14d374ea0604f70e6f39306efd948e7962fdd21cdb3e187ba461312027ebd3f5"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Taiyuan Chenyun Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "41:8a:59:77:65:e8:4f:03:f0:79:33:ef:a3:cc:39:d4"
      cert_thumbprint     = "6AA164C42049C428431BDD9377D813AB259780A8"
      cert_valid_from     = "2025-12-11"
      cert_valid_to       = "2026-12-11"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MADD0BH943"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "41:8a:59:77:65:e8:4f:03:f0:79:33:ef:a3:cc:39:d4"
      )
}
