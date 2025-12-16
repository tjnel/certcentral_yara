import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_GlobalSign_65B9DBD2477639223438D313 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-07"
      version             = "1.0"

      hash                = "72679e118a9e644211b44a57b8824ba44e23f977dfd5a00894cd300805b3e20b"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Euro Derma Cosmetics"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "65:b9:db:d2:47:76:39:22:34:38:d3:13"
      cert_thumbprint     = "B3646CC2569FA997954105804BAF0E7AE9D6FD58"
      cert_valid_from     = "2025-03-07"
      cert_valid_to       = "2026-03-08"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "210568-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "65:b9:db:d2:47:76:39:22:34:38:d3:13"
      )
}
