import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_6BD6A96F96CA98B8AA31A211 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-17"
      version             = "1.0"

      hash                = "cf1f6af7cdcb59ef2f657258818b676b339766570be08891bd67cbdb93e708ca"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Abalini"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6b:d6:a9:6f:96:ca:98:b8:aa:31:a2:11"
      cert_thumbprint     = "2CC0D87D5552CD37A7CB309B3ABE797E52347607"
      cert_valid_from     = "2025-03-17"
      cert_valid_to       = "2026-03-18"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6b:d6:a9:6f:96:ca:98:b8:aa:31:a2:11"
      )
}
