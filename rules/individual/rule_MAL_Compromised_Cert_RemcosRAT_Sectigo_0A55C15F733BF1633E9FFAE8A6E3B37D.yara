import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Sectigo_0A55C15F733BF1633E9FFAE8A6E3B37D {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-30"
      version             = "1.0"

      hash                = "d4acc0dd3b974dde3fce2ec192c8013e8ec975a71cd6ea9d805cc1992a5930ec"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osnova OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d"
      cert_thumbprint     = "591F68885FC805A10996262C93AAB498C81F3010"
      cert_valid_from     = "2020-10-30"
      cert_valid_to       = "2021-10-30"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d"
      )
}
