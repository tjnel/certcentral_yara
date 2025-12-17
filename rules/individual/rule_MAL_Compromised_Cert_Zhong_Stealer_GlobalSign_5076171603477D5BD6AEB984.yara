import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_5076171603477D5BD6AEB984 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-11"
      version             = "1.0"

      hash                = "33a942276ace165ccbc9db4966b18d0a767e2e78f4a09d2bf0845bcd2c8a356c"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "GZ.PurestJone Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:76:17:16:03:47:7d:5b:d6:ae:b9:84"
      cert_thumbprint     = "8C53168E668EF0CB2F20C3D7770830EF3CB73077"
      cert_valid_from     = "2024-04-11"
      cert_valid_to       = "2025-04-12"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440114MACL0TN54Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:76:17:16:03:47:7d:5b:d6:ae:b9:84"
      )
}
