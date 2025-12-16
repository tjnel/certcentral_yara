import "pe"

rule MAL_Compromised_Cert_Vidar_GlobalSign_5777A8DF6F72D25809EF51F2 {
   meta:
      description         = "Detects Vidar with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-07"
      version             = "1.0"

      hash                = "f8c14349fab2076bce42b0962586196baf6caadba2eb1e4dde0a2e974d283a82"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AMBER GUSTO LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:77:a8:df:6f:72:d2:58:09:ef:51:f2"
      cert_thumbprint     = "E70D63D271BFF21E7285F74081AF50562F86B7D4"
      cert_valid_from     = "2025-04-07"
      cert_valid_to       = "2026-04-08"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1217800200970"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:77:a8:df:6f:72:d2:58:09:ef:51:f2"
      )
}
