import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_648B06C27B37237B6D204BB5 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-12"
      version             = "1.0"

      hash                = "97a2d5e70f82ba56cdc8e7180c63d1fcd165704389e7362ed142f968c5b1ccaa"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Hoozoou Leeser Smart Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:8b:06:c2:7b:37:23:7b:6d:20:4b:b5"
      cert_thumbprint     = "4B9D36A0525303CC0F97567BC8755E9A61DA6C78"
      cert_valid_from     = "2025-03-12"
      cert_valid_to       = "2026-03-13"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "91330108MA2B16Q83M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:8b:06:c2:7b:37:23:7b:6d:20:4b:b5"
      )
}
