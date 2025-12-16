import "pe"

rule MAL_Compromised_Cert_BadNews_Sectigo_25BA18A267D6D8E08EBC6E2457D58D1E {
   meta:
      description         = "Detects BadNews with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-31"
      version             = "1.0"

      hash                = "a065bb515d1adaa6a3c322e49a79fdfa6655d4beac334af32ebfa9f349a71b53"
      malware             = "BadNews"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "5Y TECHNOLOGY LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e"
      cert_thumbprint     = "0B26D02A94F4C8E14222A966B005BB7D30B45786"
      cert_valid_from     = "2022-03-31"
      cert_valid_to       = "2023-03-15"

      country             = "GB"
      state               = "Essex"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e"
      )
}
