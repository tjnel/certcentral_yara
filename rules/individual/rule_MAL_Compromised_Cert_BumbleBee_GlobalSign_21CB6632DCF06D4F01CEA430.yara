import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_21CB6632DCF06D4F01CEA430 {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "bd4a1d110e65697620272aa573ed4e49eb9c236ce4b90a039bcde5a9f222cb35"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Vector"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "21:cb:66:32:dc:f0:6d:4f:01:ce:a4:30"
      cert_thumbprint     = "26A54F94E1A71FE999DB163606AD4F7F270C7DA2"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-05-17"

      country             = "RU"
      state               = "Oryol Oblast"
      locality            = "Oryol"
      email               = "???"
      rdn_serial_number   = "1195749008047"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "21:cb:66:32:dc:f0:6d:4f:01:ce:a4:30"
      )
}
