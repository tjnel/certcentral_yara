import "pe"

rule MAL_Compromised_Cert_Amadey_Sectigo_00AC0A7B9420B369AF3DDB748385B981 {
   meta:
      description         = "Detects Amadey with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-06"
      version             = "1.0"

      hash                = "b58f6d597c88e79bb34ee776227be235121b7a0f6b99170ff57ff66a96a940ed"
      malware             = "Amadey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO Tochka"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81"
      cert_thumbprint     = "15B56F8B0B22DBC7C08C00D47EE06B04FA7DF5FE"
      cert_valid_from     = "2020-11-06"
      cert_valid_to       = "2021-11-06"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81"
      )
}
