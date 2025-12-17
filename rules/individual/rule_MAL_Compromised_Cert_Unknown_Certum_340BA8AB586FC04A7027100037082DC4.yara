import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_340BA8AB586FC04A7027100037082DC4 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-07"
      version             = "1.0"

      hash                = "7a90a407385c33b3f24a100fe1a882d5604cd5aff99a6a2309d915105eaebf5f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jordan Curtis"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "34:0b:a8:ab:58:6f:c0:4a:70:27:10:00:37:08:2d:c4"
      cert_thumbprint     = "4C3CA23802D48A639C684AA97616F398850EE0DE"
      cert_valid_from     = "2025-09-07"
      cert_valid_to       = "2026-09-07"

      country             = "US"
      state               = "Texas"
      locality            = "DUNCANVILLE"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "34:0b:a8:ab:58:6f:c0:4a:70:27:10:00:37:08:2d:c4"
      )
}
