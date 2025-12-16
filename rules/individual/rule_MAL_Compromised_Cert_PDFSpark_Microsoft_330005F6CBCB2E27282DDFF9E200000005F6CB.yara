import "pe"

rule MAL_Compromised_Cert_PDFSpark_Microsoft_330005F6CBCB2E27282DDFF9E200000005F6CB {
   meta:
      description         = "Detects PDFSpark with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-26"
      version             = "1.0"

      hash                = "4a4747e861df7ecef1269f26ffc2197b4b23397be3dbaf4b4c6fc8f31c9ff0d8"
      malware             = "PDFSpark"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:f6:cb:cb:2e:27:28:2d:df:f9:e2:00:00:00:05:f6:cb"
      cert_thumbprint     = "4081C12711D8B7B51A6C21A575F6318094DFBE4D"
      cert_valid_from     = "2025-10-26"
      cert_valid_to       = "2025-10-29"

      country             = "US"
      state               = "New Hampshire"
      locality            = "Salem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:f6:cb:cb:2e:27:28:2d:df:f9:e2:00:00:00:05:f6:cb"
      )
}
