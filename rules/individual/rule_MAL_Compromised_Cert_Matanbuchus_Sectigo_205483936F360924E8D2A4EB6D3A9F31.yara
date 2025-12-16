import "pe"

rule MAL_Compromised_Cert_Matanbuchus_Sectigo_205483936F360924E8D2A4EB6D3A9F31 {
   meta:
      description         = "Detects Matanbuchus with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-02"
      version             = "1.0"

      hash                = "e58b9bbb7bcdf3e901453b7b9c9e514fed1e53565e3280353dccc77cde26a98e"
      malware             = "Matanbuchus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SATURN CONSULTANCY LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "20:54:83:93:6f:36:09:24:e8:d2:a4:eb:6d:3a:9f:31"
      cert_thumbprint     = "430DBEFF2F6DF708B03354D5D07E78400CFED8E9"
      cert_valid_from     = "2021-12-02"
      cert_valid_to       = "2022-12-02"

      country             = "GB"
      state               = "Essex"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "20:54:83:93:6f:36:09:24:e8:d2:a4:eb:6d:3a:9f:31"
      )
}
