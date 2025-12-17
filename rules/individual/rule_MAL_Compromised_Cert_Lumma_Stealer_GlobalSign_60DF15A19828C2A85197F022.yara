import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_60DF15A19828C2A85197F022 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-14"
      version             = "1.0"

      hash                = "9e39a555ccb79b2460d9808578ddd17e74754df03d216578202112c8e9506e0a"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Taigu Fulong Electronic Tech Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:df:15:a1:98:28:c2:a8:51:97:f0:22"
      cert_thumbprint     = "BBF98655F4D4ED396FBCA95F4AF8ED4EB01950A9"
      cert_valid_from     = "2024-08-14"
      cert_valid_to       = "2025-08-15"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Jinzhong"
      email               = "???"
      rdn_serial_number   = "911407265733564691"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:df:15:a1:98:28:c2:a8:51:97:f0:22"
      )
}
