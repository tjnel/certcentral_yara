import "pe"

rule MAL_Compromised_Cert_OysterLoader_GlobalSign_2ADE428D4873792ACB86F867 {
   meta:
      description         = "Detects OysterLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-21"
      version             = "1.0"

      hash                = "d57f995e5e7806cad3e8e6d54fc090e8f32a9f4a2e05afe725acf9e762dab575"
      malware             = "OysterLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "E.M.Z.A. GROUP MARKETING & DISTRIBUTION LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:de:42:8d:48:73:79:2a:cb:86:f8:67"
      cert_thumbprint     = "C96359CCCC307FABD56CE17AB05DB2E599A9DD7A"
      cert_valid_from     = "2025-11-21"
      cert_valid_to       = "2026-11-22"

      country             = "IL"
      state               = "Judea And Samaria"
      locality            = "Beitar Illit"
      email               = "???"
      rdn_serial_number   = "513845909"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:de:42:8d:48:73:79:2a:cb:86:f8:67"
      )
}
