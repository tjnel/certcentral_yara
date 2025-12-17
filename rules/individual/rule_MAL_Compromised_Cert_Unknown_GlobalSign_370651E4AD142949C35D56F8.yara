import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_370651E4AD142949C35D56F8 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "123be9b57daf144899eb1a6b2c4b8b536b7757dd7096cb5160964c401df11d0a"
      malware             = "Unknown"
      malware_type        = "Loader"
      malware_notes       = "Downloads a JavaScript remote access tool via a hardcoded URL."

      signer              = "LLC Tekhenergostroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "37:06:51:e4:ad:14:29:49:c3:5d:56:f8"
      cert_thumbprint     = "28817722CCED8931F45424627299BDBFE22F9743"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2026-06-06"

      country             = "RU"
      state               = "Moscow"
      locality            = "Troitsk"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "37:06:51:e4:ad:14:29:49:c3:5d:56:f8"
      )
}
