import "pe"

rule MAL_Compromised_Cert_Cert_Only_GlobalSign_432291EE2D1F6B4F2D5E1E00 {
   meta:
      description         = "Detects Cert Only with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-25"
      version             = "1.0"

      hash                = "8ecc9c82c7d30b2bbeebcb593e8f9372e8b20554a6805abbf10368eee4782886"
      malware             = "Cert Only"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE SP Z O O"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "43:22:91:ee:2d:1f:6b:4f:2d:5e:1e:00"
      cert_thumbprint     = "83D5809E026B355EE19ADF29CF09CB6C99E624C0"
      cert_valid_from     = "2024-04-25"
      cert_valid_to       = "2025-03-08"

      country             = "PL"
      state               = "MAZOWIECKIE"
      locality            = "WARSZAWA"
      email               = "admin@softwarepoland.com"
      rdn_serial_number   = "0000682860"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "43:22:91:ee:2d:1f:6b:4f:2d:5e:1e:00"
      )
}
