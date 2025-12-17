import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_727A09742933A54934F8E1DC {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-30"
      version             = "1.0"

      hash                = "c3273c47f3aafa0f8de22d1e8ca24cafca867cb42104973c0e7d823a35b062ab"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HD Communication Co.,Ltd"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "72:7a:09:74:29:33:a5:49:34:f8:e1:dc"
      cert_thumbprint     = "A12C37FCEEF41DBC11F41EA9C85E75A2AB279F20"
      cert_valid_from     = "2023-10-30"
      cert_valid_to       = "2024-12-27"

      country             = "KR"
      state               = "Seoul"
      locality            = "Geumcheon-gu"
      email               = "???"
      rdn_serial_number   = "110111-4267492"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "72:7a:09:74:29:33:a5:49:34:f8:e1:dc"
      )
}
