import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_330002C012FD70C2539C6E20C100000002C012 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-04"
      version             = "1.0"

      hash                = "85d02a6af9729fef603c18adbe3e080f4682b16d13951882311ddb018341253b"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SRI NOVA SOLUTIONS, INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:c0:12:fd:70:c2:53:9c:6e:20:c1:00:00:00:02:c0:12"
      cert_thumbprint     = "C3E86B836E0F2683FCC2F0CE50773D321B703BF5"
      cert_valid_from     = "2025-05-04"
      cert_valid_to       = "2025-05-07"

      country             = "US"
      state               = "New York"
      locality            = "Staten Island"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:c0:12:fd:70:c2:53:9c:6e:20:c1:00:00:00:02:c0:12"
      )
}
