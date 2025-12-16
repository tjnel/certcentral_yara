import "pe"

rule MAL_Compromised_Cert_XRed_GlobalSign_50A2CABF817DCB14F6313DE6 {
   meta:
      description         = "Detects XRed with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-23"
      version             = "1.0"

      hash                = "70ed363667ec9761867c6e5da32a6486d2c52e846e03e6c535545ad4a2a973f5"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Renren Aipin Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:a2:ca:bf:81:7d:cb:14:f6:31:3d:e6"
      cert_thumbprint     = "C4FA6706FB6CCA2CBEDC6638905B4CF08B4984B1"
      cert_valid_from     = "2025-07-23"
      cert_valid_to       = "2026-07-24"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:a2:ca:bf:81:7d:cb:14:f6:31:3d:e6"
      )
}
