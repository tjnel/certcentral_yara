import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300068DF638676D7B9B83BBDE000000068DF6 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "18d2b0d6570896e86fb5478acfa752d6ae0afe9e79859e2d0de27720db20184b"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THROGGS NECK PETS INCORPORATED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:8d:f6:38:67:6d:7b:9b:83:bb:de:00:00:00:06:8d:f6"
      cert_thumbprint     = "CABAE0BE0F0343792E984FD73040EF3D86243A7D"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2025-12-07"

      country             = "US"
      state               = "New York"
      locality            = "BRONX"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:8d:f6:38:67:6d:7b:9b:83:bb:de:00:00:00:06:8d:f6"
      )
}
