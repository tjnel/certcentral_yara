import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_33000579BB23E9DB7D00BF761A0000000579BB {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-26"
      version             = "1.0"

      hash                = "c48d1803b84e1da6cb53f0bd279376247fbb0ae1d32115c44ad29bdbccbb1b71"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LES LOGICIELS SYSTAMEX INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:79:bb:23:e9:db:7d:00:bf:76:1a:00:00:00:05:79:bb"
      cert_thumbprint     = "4A109720C3D9CAAD4A88A285AB058A1ACF1BF6A6"
      cert_valid_from     = "2025-11-26"
      cert_valid_to       = "2025-11-29"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Basile-le-Grand"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:79:bb:23:e9:db:7d:00:bf:76:1a:00:00:00:05:79:bb"
      )
}
