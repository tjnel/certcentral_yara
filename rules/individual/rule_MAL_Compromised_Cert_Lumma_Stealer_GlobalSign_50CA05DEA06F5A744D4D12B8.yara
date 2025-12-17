import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_50CA05DEA06F5A744D4D12B8 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-06"
      version             = "1.0"

      hash                = "5c879ad7c6b5670812c5f79dffb4e4822c13d84dd35a29fe8bc4ae82f62834cb"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Burnoris Niraver Hirtuden Technolog Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:ca:05:de:a0:6f:5a:74:4d:4d:12:b8"
      cert_thumbprint     = "CAF837D41630E1371BFE97F14C61A3BF1F7B20D2"
      cert_valid_from     = "2024-03-06"
      cert_valid_to       = "2025-03-07"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "91330103MA28W1DR98"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:ca:05:de:a0:6f:5a:74:4d:4d:12:b8"
      )
}
