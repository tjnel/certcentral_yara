import "pe"

rule MAL_Compromised_Cert_Vidar_Microsoft_33000518E15B387314896695710000000518E1 {
   meta:
      description         = "Detects Vidar with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-29"
      version             = "1.0"

      hash                = "f92df84e92093e0e6e0ab44630a777689157f5433c7b007e590f917a5524068b"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EARNEST PROJECTS INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:18:e1:5b:38:73:14:89:66:95:71:00:00:00:05:18:e1"
      cert_thumbprint     = "C9A76002341946F2890FF614355D360BE55CEE4E"
      cert_valid_from     = "2025-10-29"
      cert_valid_to       = "2025-11-01"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:18:e1:5b:38:73:14:89:66:95:71:00:00:00:05:18:e1"
      )
}
