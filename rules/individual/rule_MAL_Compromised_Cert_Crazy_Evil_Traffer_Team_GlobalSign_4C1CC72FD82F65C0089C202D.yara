import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_4C1CC72FD82F65C0089C202D {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-29"
      version             = "1.0"

      hash                = "45d177fb552f52d54c3f82aa9634e9af0ea4abf8939b70313989d1a7860818e9"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Infostealer"
      malware_notes       = "Fake ledger wallet installer."

      signer              = "PAPER & COTTON LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4c:1c:c7:2f:d8:2f:65:c0:08:9c:20:2d"
      cert_thumbprint     = "95EF120A21BCD680CA2E8F2A1ED3533753DF6A44"
      cert_valid_from     = "2025-12-29"
      cert_valid_to       = "2026-12-30"

      country             = "GB"
      state               = "Gloucestershire"
      locality            = "Wotton-under-Edge"
      email               = "???"
      rdn_serial_number   = "06039818"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4c:1c:c7:2f:d8:2f:65:c0:08:9c:20:2d"
      )
}
