import "pe"

rule MAL_Compromised_Cert_PDFSpark_Microsoft_3300068102C2D97F2FA0C377B0000000068102 {
   meta:
      description         = "Detects PDFSpark with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-30"
      version             = "1.0"

      hash                = "8e1fc5417df402b45b544858bc3526ccc8177af48341a9412e5e98a7fc19fd66"
      malware             = "PDFSpark"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:81:02:c2:d9:7f:2f:a0:c3:77:b0:00:00:00:06:81:02"
      cert_thumbprint     = "FA5C45BB05CF999E67E32BFE0B87EEA7C1C407B9"
      cert_valid_from     = "2025-11-30"
      cert_valid_to       = "2025-12-03"

      country             = "US"
      state               = "New Hampshire"
      locality            = "Salem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:81:02:c2:d9:7f:2f:a0:c3:77:b0:00:00:00:06:81:02"
      )
}
