import "pe"

rule MAL_Compromised_Cert_PDFSpark_Microsoft_330005057672A0AAC2A4B79566000000050576 {
   meta:
      description         = "Detects PDFSpark with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-24"
      version             = "1.0"

      hash                = "00f0338e7caa630d10347a5bebed83bb4c11ebce34f4470a213f93828a66addf"
      malware             = "PDFSpark"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:05:76:72:a0:aa:c2:a4:b7:95:66:00:00:00:05:05:76"
      cert_thumbprint     = "E3EFCCB48A282FE2091CBA889D79BF65DEF49607"
      cert_valid_from     = "2025-10-24"
      cert_valid_to       = "2025-10-27"

      country             = "US"
      state               = "New Hampshire"
      locality            = "Salem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:05:76:72:a0:aa:c2:a4:b7:95:66:00:00:00:05:05:76"
      )
}
