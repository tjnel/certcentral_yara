import "pe"

rule MAL_Compromised_Cert_TA505_Sectigo_51AEAD5A9AB2D841B449FA82DE3A8A00 {
   meta:
      description         = "Detects TA505 with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-05"
      version             = "1.0"

      hash                = "89a9f09823152d3c5cbe29c667618e128fc8c0677ecec217fb7c2ccae75a7bf2"
      malware             = "TA505"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Corsair Software Solution Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00"
      cert_thumbprint     = "56D8BEAC4650E4A25F0C7D338FE12A8285C1D388"
      cert_valid_from     = "2020-08-05"
      cert_valid_to       = "2021-08-05"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00"
      )
}
