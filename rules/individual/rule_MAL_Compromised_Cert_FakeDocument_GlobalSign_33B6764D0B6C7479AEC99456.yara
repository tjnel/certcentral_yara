import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_33B6764D0B6C7479AEC99456 {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-14"
      version             = "1.0"

      hash                = "0f5de795b2a1453dd87d64e4c683177c1ac98d559b4c9c255bbe8493ea10fabb"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MOKOPANE SHERIFF (PTY) LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "33:b6:76:4d:0b:6c:74:79:ae:c9:94:56"
      cert_thumbprint     = "AE1D65CC18597A6AAC6C6A45A63B3D47B7CE1A8B"
      cert_valid_from     = "2025-10-14"
      cert_valid_to       = "2026-10-15"

      country             = "ZA"
      state               = "Limpopo"
      locality            = "Mokopane"
      email               = "admin@mokopanesheriff.com"
      rdn_serial_number   = "K2022681231"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "33:b6:76:4d:0b:6c:74:79:ae:c9:94:56"
      )
}
