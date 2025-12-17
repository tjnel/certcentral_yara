import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_746BFAEDF11F1BDDBA78ECE2 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-06"
      version             = "1.0"

      hash                = "fe32b577785d1bb81f90a3a0e5793d6eead1128df3fe5841860aa9a1e1ddc8be"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KRONOS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "74:6b:fa:ed:f1:1f:1b:dd:ba:78:ec:e2"
      cert_thumbprint     = "40375B72A873FB48A64220AFF92EE33DE7C15286"
      cert_valid_from     = "2025-03-06"
      cert_valid_to       = "2026-03-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700456960"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "74:6b:fa:ed:f1:1f:1b:dd:ba:78:ec:e2"
      )
}
