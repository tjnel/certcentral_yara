import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_172C26AE164BCD6BEFEC180E {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-03"
      version             = "1.0"

      hash                = "3a338725967f6bb7fc3d5245bc40371742f46caae99f0db23e52f81c748091ab"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Shenzhen Xiangyou Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "17:2c:26:ae:16:4b:cd:6b:ef:ec:18:0e"
      cert_thumbprint     = "da71e8a37f0f99dd7652d95fec40361409dd16ed"
      cert_valid_from     = "2025-01-03"
      cert_valid_to       = "2026-01-04"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5EFLM089"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "17:2c:26:ae:16:4b:cd:6b:ef:ec:18:0e"
      )
}
