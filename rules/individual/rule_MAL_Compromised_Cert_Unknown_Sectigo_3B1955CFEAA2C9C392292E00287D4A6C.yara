import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_3B1955CFEAA2C9C392292E00287D4A6C {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-25"
      version             = "1.0"

      hash                = "f1787b9553ce260b889cbb40b456d62f2cfa01b10f7e512a3528790c65640669"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MECHA MANGA - FZCO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "3b:19:55:cf:ea:a2:c9:c3:92:29:2e:00:28:7d:4a:6c"
      cert_thumbprint     = "1F3CCE31883C9EF47711A1EE96294E479CE69CFB"
      cert_valid_from     = "2024-03-25"
      cert_valid_to       = "2025-03-25"

      country             = "AE"
      state               = "Dubai"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "3b:19:55:cf:ea:a2:c9:c3:92:29:2e:00:28:7d:4a:6c"
      )
}
