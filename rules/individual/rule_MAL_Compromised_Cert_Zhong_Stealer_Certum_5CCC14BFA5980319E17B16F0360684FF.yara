import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_5CCC14BFA5980319E17B16F0360684FF {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-07"
      version             = "1.0"

      hash                = "f0373871da028119a2726637859014eb63d2c7770924fe17b47199a6e6255aa6"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Changdu Wopu Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5c:cc:14:bf:a5:98:03:19:e1:7b:16:f0:36:06:84:ff"
      cert_thumbprint     = "E5A604EE112216277E35FA9536A2E9086991EDC8"
      cert_valid_from     = "2025-11-07"
      cert_valid_to       = "2026-11-07"

      country             = "CN"
      state               = "西藏自治区"
      locality            = "昌都市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5c:cc:14:bf:a5:98:03:19:e1:7b:16:f0:36:06:84:ff"
      )
}
