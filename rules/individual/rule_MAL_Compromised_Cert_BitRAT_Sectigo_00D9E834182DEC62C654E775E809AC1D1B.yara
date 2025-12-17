import "pe"

rule MAL_Compromised_Cert_BitRAT_Sectigo_00D9E834182DEC62C654E775E809AC1D1B {
   meta:
      description         = "Detects BitRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-26"
      version             = "1.0"

      hash                = "645dbb6df97018fafb4285dc18ea374c721c86349cb75494c7d63d6a6afc27e6"
      malware             = "BitRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FoodLehto Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b"
      cert_thumbprint     = "5BB983693823DBEFA292C86D93B92A49EC6F9B26"
      cert_valid_from     = "2021-02-26"
      cert_valid_to       = "2022-02-26"

      country             = "FI"
      state               = "Varsinais-Suomi"
      locality            = "Uusikaupunki"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b"
      )
}
