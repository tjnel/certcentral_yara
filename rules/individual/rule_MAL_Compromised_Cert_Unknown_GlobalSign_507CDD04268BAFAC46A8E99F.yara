import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_507CDD04268BAFAC46A8E99F {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-11"
      version             = "1.0"

      hash                = "85032533512bdb54e039a85d7efffb0ff9763c91ecb514e4be57fb3de368e6c3"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tunz Entertainment Russia LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:7c:dd:04:26:8b:af:ac:46:a8:e9:9f"
      cert_thumbprint     = "FC2B2367EDF50ABE75A52982505B1C8DC93EFA79"
      cert_valid_from     = "2025-03-11"
      cert_valid_to       = "2026-03-12"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1167746444689"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:7c:dd:04:26:8b:af:ac:46:a8:e9:9f"
      )
}
