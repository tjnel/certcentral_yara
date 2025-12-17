import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_238C51ADD3AC9CD0AB808018 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-21"
      version             = "1.0"

      hash                = "58c381350225859f5522f84b9d74621f254826c7a082b832f29b3fddc5c61289"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Medexpert LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:8c:51:ad:d3:ac:9c:d0:ab:80:80:18"
      cert_thumbprint     = "0549367AAF46C4351BDD81C3FDAAD73F49BC7E0C"
      cert_valid_from     = "2025-03-21"
      cert_valid_to       = "2026-03-22"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1227800025969"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:8c:51:ad:d3:ac:9c:d0:ab:80:80:18"
      )
}
