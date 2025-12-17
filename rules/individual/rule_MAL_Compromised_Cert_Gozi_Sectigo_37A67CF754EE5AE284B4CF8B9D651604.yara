import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_37A67CF754EE5AE284B4CF8B9D651604 {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-02"
      version             = "1.0"

      hash                = "da5edd26691ace1af31cfc1e1ae61de36e1c82f02aba24835ca566fe0c9b71a0"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FORTH PROPERTY LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "37:a6:7c:f7:54:ee:5a:e2:84:b4:cf:8b:9d:65:16:04"
      cert_thumbprint     = "7589B73A1B9A28A5AE18586D7C496D9B3971C727"
      cert_valid_from     = "2021-04-02"
      cert_valid_to       = "2022-04-02"

      country             = "GB"
      state               = "Midlothian"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "37:a6:7c:f7:54:ee:5a:e2:84:b4:cf:8b:9d:65:16:04"
      )
}
