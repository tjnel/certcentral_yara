import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_754022596DA5B16478C5E880ED2D730F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-16"
      version             = "1.0"

      hash                = "36d4a0c46a0b9613b7f4ab38a9bf1a8ee3d54e059f2451f20e999a7b49b9af56"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Yongji Xiaodong Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "75:40:22:59:6d:a5:b1:64:78:c5:e8:80:ed:2d:73:0f"
      cert_thumbprint     = "3148D6576C067EE43DAACBFD3B34C033EEE1DB53"
      cert_valid_from     = "2025-09-16"
      cert_valid_to       = "2026-09-16"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "75:40:22:59:6d:a5:b1:64:78:c5:e8:80:ed:2d:73:0f"
      )
}
