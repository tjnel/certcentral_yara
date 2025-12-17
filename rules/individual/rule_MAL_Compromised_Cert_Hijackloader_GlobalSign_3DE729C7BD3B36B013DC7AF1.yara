import "pe"

rule MAL_Compromised_Cert_Hijackloader_GlobalSign_3DE729C7BD3B36B013DC7AF1 {
   meta:
      description         = "Detects Hijackloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-30"
      version             = "1.0"

      hash                = "42840d9af32e3fa50208aed35792195d2094d7c9126b90152df2cb76e296f272"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Exit"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3d:e7:29:c7:bd:3b:36:b0:13:dc:7a:f1"
      cert_thumbprint     = "468FCFCD44141432A60927AAC4ABEFBB4312C6A6"
      cert_valid_from     = "2025-05-30"
      cert_valid_to       = "2026-05-31"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "1185476007133"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3d:e7:29:c7:bd:3b:36:b0:13:dc:7a:f1"
      )
}
