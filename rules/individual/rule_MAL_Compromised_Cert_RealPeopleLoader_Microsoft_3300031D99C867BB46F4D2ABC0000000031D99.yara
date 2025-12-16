import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_3300031D99C867BB46F4D2ABC0000000031D99 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "949675ef054d7a94eeeae058ae9ee413c68289aac88ac7ff5f043f30565fd2f5"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "POINT CLICK LEARN, INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:1d:99:c8:67:bb:46:f4:d2:ab:c0:00:00:00:03:1d:99"
      cert_thumbprint     = "94B44CBB7B69D4CA6E55A014DF1F46F3AB55B62E"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2025-06-08"

      country             = "US"
      state               = "Pennsylvania"
      locality            = "Mc Kean"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:1d:99:c8:67:bb:46:f4:d2:ab:c0:00:00:00:03:1d:99"
      )
}
