import "pe"

rule MAL_Compromised_Cert_SearchLoader_Microsoft_33000621BC3C359A50E123AB850000000621BC {
   meta:
      description         = "Detects SearchLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-13"
      version             = "1.0"

      hash                = "cb8053c819c587f3e81b0201d27d686ccdd3ca042cb4c2ed50b84e7f2ee2232f"
      malware             = "SearchLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hamilton Vision and Eye Care, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:21:bc:3c:35:9a:50:e1:23:ab:85:00:00:00:06:21:bc"
      cert_thumbprint     = "40CDBA5439F8E4F5D637EE19754D32E97EEA4EFD"
      cert_valid_from     = "2025-11-13"
      cert_valid_to       = "2025-11-16"

      country             = "US"
      state               = "Alabama"
      locality            = "HAMILTON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:21:bc:3c:35:9a:50:e1:23:ab:85:00:00:00:06:21:bc"
      )
}
