import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_3300020EDF3515BE59E6A8EC97000000020EDF {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-12"
      version             = "1.0"

      hash                = "b1e48bdb7dcdcca142d457bb033633edd5c1b599207c643de3ceee55b20571ec"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "志超 柴"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:0e:df:35:15:be:59:e6:a8:ec:97:00:00:00:02:0e:df"
      cert_thumbprint     = "6B3553EFDCBE075492A4FB28B5C7063922F637BD"
      cert_valid_from     = "2025-03-12"
      cert_valid_to       = "2025-03-15"

      country             = "CN"
      state               = "???"
      locality            = "平南"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:0e:df:35:15:be:59:e6:a8:ec:97:00:00:00:02:0e:df"
      )
}
