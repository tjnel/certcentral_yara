import "pe"

rule MAL_Compromised_Cert_FakeCursorAI_GlobalSign_6F4DC3F942D3C01E6DE63ED4 {
   meta:
      description         = "Detects FakeCursorAI with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-07"
      version             = "1.0"

      hash                = "653bf569911aeb4ce07dda01aa9402a3df4060487b4e7a040d72e20462a938e1"
      malware             = "FakeCursorAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Tekhnicheskoe Snabzhenie"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6f:4d:c3:f9:42:d3:c0:1e:6d:e6:3e:d4"
      cert_thumbprint     = "3C9DDCB42EA7FB6BAA438E9A5CC4723B0FF4C90F"
      cert_valid_from     = "2025-12-07"
      cert_valid_to       = "2026-07-08"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1197746521345"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6f:4d:c3:f9:42:d3:c0:1e:6d:e6:3e:d4"
      )
}
