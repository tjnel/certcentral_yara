import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_22CFC84BD7696394B5169DD21E1CF34D {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-07"
      version             = "1.0"

      hash                = "13bfddbe0cd6050de5d66030f14c4a0e66550845461429ebd70b642b7b70f741"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cockos Incorporated"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "22:cf:c8:4b:d7:69:63:94:b5:16:9d:d2:1e:1c:f3:4d"
      cert_thumbprint     = "841CB9672DD77039E8EA94FFE95E891BC0799442"
      cert_valid_from     = "2025-04-07"
      cert_valid_to       = "2025-12-18"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "22:cf:c8:4b:d7:69:63:94:b5:16:9d:d2:1e:1c:f3:4d"
      )
}
