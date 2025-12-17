import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_424E89A44FF616A6183251F7 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-11"
      version             = "1.0"

      hash                = "1f0f5173c6aae129e6cd5994da53b510497be2ba7f2ebf50fb0cb298314b0c8a"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "PrimeSnap Technologies Network Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:4e:89:a4:4f:f6:16:a6:18:32:51:f7"
      cert_thumbprint     = "FF9B29C594ECC88BDE9AB852D7195CAFECFB2060"
      cert_valid_from     = "2024-11-11"
      cert_valid_to       = "2025-11-12"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101078418722E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:4e:89:a4:4f:f6:16:a6:18:32:51:f7"
      )
}
