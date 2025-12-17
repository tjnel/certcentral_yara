import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_16668BF1446C1C20F26BE641 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-10"
      version             = "1.0"

      hash                = "84a71f90d0557682833992e3388949775e979efea501a8402496828112d8b814"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FORTUNE PRINT CENTRE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "16:66:8b:f1:44:6c:1c:20:f2:6b:e6:41"
      cert_thumbprint     = "7A540E69CC7BEBAF9E6D0850176B9920F0D5D0FF"
      cert_valid_from     = "2025-01-10"
      cert_valid_to       = "2026-01-11"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "llcvulkan1@gmail.com"
      rdn_serial_number   = "PVT-RXUQBEJ"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "16:66:8b:f1:44:6c:1c:20:f2:6b:e6:41"
      )
}
