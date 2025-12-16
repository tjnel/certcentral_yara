import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_3300045DC9932C64B8919CD25C000000045DC9 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-16"
      version             = "1.0"

      hash                = "38c60fd0e51b21b580552430f1ef55b7a41a1c6894ee61edc0707644d6c0b977"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MRDUFORT VENTES/SERVICE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:5d:c9:93:2c:64:b8:91:9c:d2:5c:00:00:00:04:5d:c9"
      cert_thumbprint     = "A6F7C691297D6D9C3FC5E835E160A460E301B99E"
      cert_valid_from     = "2025-09-16"
      cert_valid_to       = "2025-09-19"

      country             = "CA"
      state               = "Québec"
      locality            = "NUN'S ISLAND"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:5d:c9:93:2c:64:b8:91:9c:d2:5c:00:00:00:04:5d:c9"
      )
}
