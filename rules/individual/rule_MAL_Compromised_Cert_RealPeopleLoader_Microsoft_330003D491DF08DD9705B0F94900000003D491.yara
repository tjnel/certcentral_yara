import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_330003D491DF08DD9705B0F94900000003D491 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-25"
      version             = "1.0"

      hash                = "a069032baf4fe2514ec106c5731a035361dfefd0b68a23c782ac7ad82428da7d"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ZONA ENTERPRISES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:d4:91:df:08:dd:97:05:b0:f9:49:00:00:00:03:d4:91"
      cert_thumbprint     = "7BCA2D50D3787AD89A0D116CECEA2280530F6368"
      cert_valid_from     = "2025-05-25"
      cert_valid_to       = "2025-05-28"

      country             = "US"
      state               = "Arizona"
      locality            = "Chandler"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:d4:91:df:08:dd:97:05:b0:f9:49:00:00:00:03:d4:91"
      )
}
