import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_524AF164B507AB0FDE7FFC46 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-31"
      version             = "1.0"

      hash                = "ae27d090d2831a9a7ffcc60af70f858cda67ef36d22b81099d9a67762717cffa"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangzhou TOP WELL Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "52:4a:f1:64:b5:07:ab:0f:de:7f:fc:46"
      cert_thumbprint     = "14BDF31882F0C8F946FAC148D6CB9EF658F32B39"
      cert_valid_from     = "2024-10-31"
      cert_valid_to       = "2025-11-01"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "913301086829037759"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "52:4a:f1:64:b5:07:ab:0f:de:7f:fc:46"
      )
}
