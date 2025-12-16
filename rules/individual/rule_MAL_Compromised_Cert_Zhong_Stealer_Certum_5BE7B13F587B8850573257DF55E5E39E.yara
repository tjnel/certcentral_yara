import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_5BE7B13F587B8850573257DF55E5E39E {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-18"
      version             = "1.0"

      hash                = "873ea83b3507d8391b1b66f0f3d57cefff4307463b018eec09abbff601c83d30"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shandong Saibo Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5b:e7:b1:3f:58:7b:88:50:57:32:57:df:55:e5:e3:9e"
      cert_thumbprint     = "9604C61D97B1AF3BF1E5C00E707DF524E1491678"
      cert_valid_from     = "2025-11-18"
      cert_valid_to       = "2026-11-18"

      country             = "CN"
      state               = "Shandong"
      locality            = "Taian"
      email               = "???"
      rdn_serial_number   = "91370902MAC7ANU62H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5b:e7:b1:3f:58:7b:88:50:57:32:57:df:55:e5:e3:9e"
      )
}
