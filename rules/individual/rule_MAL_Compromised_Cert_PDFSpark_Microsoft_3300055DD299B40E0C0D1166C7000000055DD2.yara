import "pe"

rule MAL_Compromised_Cert_PDFSpark_Microsoft_3300055DD299B40E0C0D1166C7000000055DD2 {
   meta:
      description         = "Detects PDFSpark with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-20"
      version             = "1.0"

      hash                = "4fa777e1392037fde13b8e93b7d69427926fca5000b816f562e829c9246f46c9"
      malware             = "PDFSpark"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:5d:d2:99:b4:0e:0c:0d:11:66:c7:00:00:00:05:5d:d2"
      cert_thumbprint     = "CAA635133D0CBD12C822A2C7BCC8FC9A95286E5A"
      cert_valid_from     = "2025-11-20"
      cert_valid_to       = "2025-11-23"

      country             = "US"
      state               = "New Hampshire"
      locality            = "Salem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:5d:d2:99:b4:0e:0c:0d:11:66:c7:00:00:00:05:5d:d2"
      )
}
