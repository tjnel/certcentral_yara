import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_330002F6B621C3DACF7C0F844C00000002F6B6 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-20"
      version             = "1.0"

      hash                = "67a4f229c6426e032e071a9826cd3c2462bdd69c372b7d4da7f77b8fb9846705"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AMAVI CONSULTING LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:f6:b6:21:c3:da:cf:7c:0f:84:4c:00:00:00:02:f6:b6"
      cert_thumbprint     = "9FC7AF90537A25295C838DF0BA8B61308F55A7EB"
      cert_valid_from     = "2025-05-20"
      cert_valid_to       = "2025-05-23"

      country             = "US"
      state               = "Arizona"
      locality            = "Glendale"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:f6:b6:21:c3:da:cf:7c:0f:84:4c:00:00:00:02:f6:b6"
      )
}
