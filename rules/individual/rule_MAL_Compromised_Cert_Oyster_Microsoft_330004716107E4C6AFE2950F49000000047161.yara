import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330004716107E4C6AFE2950F49000000047161 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-23"
      version             = "1.0"

      hash                = "32b0f69e2d046cb835060751fcda28b633cbbd964e6e54dbbc1482fff4d51b57"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "KUTTANADAN CREATIONS INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:71:61:07:e4:c6:af:e2:95:0f:49:00:00:00:04:71:61"
      cert_thumbprint     = "A81B9CB3F76D8AD099102B4F05531DD1C877D845"
      cert_valid_from     = "2025-09-23"
      cert_valid_to       = "2025-09-26"

      country             = "US"
      state               = "New York"
      locality            = "Floral Park"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:71:61:07:e4:c6:af:e2:95:0f:49:00:00:00:04:71:61"
      )
}
