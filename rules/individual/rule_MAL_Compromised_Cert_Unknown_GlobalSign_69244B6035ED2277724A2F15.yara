import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_69244B6035ED2277724A2F15 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-27"
      version             = "1.0"

      hash                = "1b173e271544684f09d4a98414fe89b137fae7a7438527e31d6ff0e160f0cf9d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PREMERA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:24:4b:60:35:ed:22:77:72:4a:2f:15"
      cert_thumbprint     = "01cfd115329264c5240ff1183ec80346abbf0ad87e2c4cda4325ef029dcaebcf"
      cert_valid_from     = "2024-12-27"
      cert_valid_to       = "2025-12-28"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700409506"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:24:4b:60:35:ed:22:77:72:4a:2f:15"
      )
}
