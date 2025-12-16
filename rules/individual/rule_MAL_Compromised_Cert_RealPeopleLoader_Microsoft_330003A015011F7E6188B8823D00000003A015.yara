import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_330003A015011F7E6188B8823D00000003A015 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "3fd6f78600d58c88f734b01fff2e605087d1c2957cc1d6c2867df575816c9dd4"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A TO Z ENTERPRISES, INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:a0:15:01:1f:7e:61:88:b8:82:3d:00:00:00:03:a0:15"
      cert_thumbprint     = "A0F10F17F30D8072706C62474A624F19B4E35276"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2025-05-12"

      country             = "US"
      state               = "Utah"
      locality            = "Salt Lake City"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:a0:15:01:1f:7e:61:88:b8:82:3d:00:00:00:03:a0:15"
      )
}
