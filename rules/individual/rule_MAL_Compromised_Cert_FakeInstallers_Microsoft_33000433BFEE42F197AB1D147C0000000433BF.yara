import "pe"

rule MAL_Compromised_Cert_FakeInstallers_Microsoft_33000433BFEE42F197AB1D147C0000000433BF {
   meta:
      description         = "Detects FakeInstallers with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-02"
      version             = "1.0"

      hash                = "07d6152464eb5b290ddbc590496fe22028bcf2bc4c669b7311d416db322b384d"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "56 SQUARED PARTNERS LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:33:bf:ee:42:f1:97:ab:1d:14:7c:00:00:00:04:33:bf"
      cert_thumbprint     = "B8149FE5681089DF2F244114E0448B4A70AECDDA"
      cert_valid_from     = "2025-09-02"
      cert_valid_to       = "2025-09-05"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:33:bf:ee:42:f1:97:ab:1d:14:7c:00:00:00:04:33:bf"
      )
}
