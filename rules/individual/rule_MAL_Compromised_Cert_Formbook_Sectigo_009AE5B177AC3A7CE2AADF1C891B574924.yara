import "pe"

rule MAL_Compromised_Cert_Formbook_Sectigo_009AE5B177AC3A7CE2AADF1C891B574924 {
   meta:
      description         = "Detects Formbook with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-16"
      version             = "1.0"

      hash                = "3bfe5c5cfe153699f3627845f5f9b44c7ccc09b9cc8e34203d73c993439510a9"
      malware             = "Formbook"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO Kolorit"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24"
      cert_thumbprint     = "13EF12700D995A3527EABE0D9BAC3E96332FAF1E"
      cert_valid_from     = "2020-12-16"
      cert_valid_to       = "2021-12-16"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24"
      )
}
