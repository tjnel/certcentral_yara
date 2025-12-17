import "pe"

rule MAL_Compromised_Cert_Amadey_Sectigo_6000F8C02B0A15B1E53B8399845FADDF {
   meta:
      description         = "Detects Amadey with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-08"
      version             = "1.0"

      hash                = "8102d5d284037c4b27a86bf0308e91dd07efe53e825099ef92b03a291c31d505"
      malware             = "Amadey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAY LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df"
      cert_thumbprint     = "B08379EF00D1D83AA0ADD6DF7D9040C2DAA6B1D7"
      cert_valid_from     = "2022-02-08"
      cert_valid_to       = "2023-02-08"

      country             = "GB"
      state               = "East Sussex"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df"
      )
}
