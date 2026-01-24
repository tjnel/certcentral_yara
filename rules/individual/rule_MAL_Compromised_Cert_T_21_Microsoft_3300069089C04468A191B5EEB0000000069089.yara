import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300069089C04468A191B5EEB0000000069089 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-20"
      version             = "1.0"

      hash                = "76172e368def55cfa8be830b8ed587cd59779f899ccc577c24f953b13cf6d591"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:90:89:c0:44:68:a1:91:b5:ee:b0:00:00:00:06:90:89"
      cert_thumbprint     = "6F63322DE5A281D6D8FDDCFD396B03BFE129C466"
      cert_valid_from     = "2026-01-20"
      cert_valid_to       = "2026-01-23"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:90:89:c0:44:68:a1:91:b5:ee:b0:00:00:00:06:90:89"
      )
}
