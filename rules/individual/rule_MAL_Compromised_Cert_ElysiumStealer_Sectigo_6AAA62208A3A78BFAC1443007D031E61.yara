import "pe"

rule MAL_Compromised_Cert_ElysiumStealer_Sectigo_6AAA62208A3A78BFAC1443007D031E61 {
   meta:
      description         = "Detects ElysiumStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-17"
      version             = "1.0"

      hash                = "f1a3ae71cced897b8a70543e3c5ee2ef093c6e3e3999801889a66d3235ea8569"
      malware             = "ElysiumStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Solar LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "6a:aa:62:20:8a:3a:78:bf:ac:14:43:00:7d:03:1e:61"
      cert_thumbprint     = "AC28A02E0EA20A35F60CF431542C471C0FA48A06"
      cert_valid_from     = "2020-12-17"
      cert_valid_to       = "2021-12-17"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "6a:aa:62:20:8a:3a:78:bf:ac:14:43:00:7d:03:1e:61"
      )
}
