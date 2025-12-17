import "pe"

rule MAL_Compromised_Cert_FakeNordpass_GlobalSign_193FA09306CB8B5D056F975B {
   meta:
      description         = "Detects FakeNordpass with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-18"
      version             = "1.0"

      hash                = "177eaa6c42960cc6fcff3726f13fba1eb5576fa47415c505cd49909e69812b1a"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Vector LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "19:3f:a0:93:06:cb:8b:5d:05:6f:97:5b"
      cert_thumbprint     = "C683252101A7099D9AC5B37C54275A6E766516D4"
      cert_valid_from     = "2025-04-18"
      cert_valid_to       = "2026-04-19"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1227800144923"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "19:3f:a0:93:06:cb:8b:5d:05:6f:97:5b"
      )
}
