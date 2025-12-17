import "pe"

rule MAL_Compromised_Cert_Dridex_Sectigo_3B777165B125BCCC181D0BAC3F5B55B3 {
   meta:
      description         = "Detects Dridex with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-07"
      version             = "1.0"

      hash                = "4a246227c6e8b90ca664792a9d6ced9f1e7c20283891bbb722623ba17aa266de"
      malware             = "Dridex"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STAND ALONE MUSIC LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "3b:77:71:65:b1:25:bc:cc:18:1d:0b:ac:3f:5b:55:b3"
      cert_thumbprint     = "A5887C72B22F81884E714EDEC711E52FDC60EA37"
      cert_valid_from     = "2020-12-07"
      cert_valid_to       = "2021-12-07"

      country             = "GB"
      state               = "???"
      locality            = "LONDON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "3b:77:71:65:b1:25:bc:cc:18:1d:0b:ac:3f:5b:55:b3"
      )
}
