import "pe"

rule MAL_Compromised_Cert_CastleRAT_GlobalSign_2DE9CB84E3F811E6FEB0A6DD {
   meta:
      description         = "Detects CastleRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-27"
      version             = "1.0"

      hash                = "6d93dfa327498ec9d6c754056665e36bc809e8f729112cbe4cf68583f5bf3ebe"
      malware             = "CastleRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LOUNGE LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2d:e9:cb:84:e3:f8:11:e6:fe:b0:a6:dd"
      cert_thumbprint     = "4A5FE69AFF51A41A116FEAC0D8EE73E8D4CFA7E4"
      cert_valid_from     = "2025-02-27"
      cert_valid_to       = "2026-02-28"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700674198"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2d:e9:cb:84:e3:f8:11:e6:fe:b0:a6:dd"
      )
}
