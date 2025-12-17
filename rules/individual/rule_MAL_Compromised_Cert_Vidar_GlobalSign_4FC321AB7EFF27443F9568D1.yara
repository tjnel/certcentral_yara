import "pe"

rule MAL_Compromised_Cert_Vidar_GlobalSign_4FC321AB7EFF27443F9568D1 {
   meta:
      description         = "Detects Vidar with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-29"
      version             = "1.0"

      hash                = "8f1b55ae725ecf5c3043d390b17eb3d03e9b9681fede65bfea1f6e7cba8e3073"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Legal Center"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4f:c3:21:ab:7e:ff:27:44:3f:95:68:d1"
      cert_thumbprint     = "AE0EDCDB222729CC469304BAFB5F5F8F2AAEF2BB"
      cert_valid_from     = "2025-09-29"
      cert_valid_to       = "2026-04-11"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4f:c3:21:ab:7e:ff:27:44:3f:95:68:d1"
      )
}
