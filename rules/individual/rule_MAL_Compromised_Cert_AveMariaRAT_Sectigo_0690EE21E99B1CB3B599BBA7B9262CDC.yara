import "pe"

rule MAL_Compromised_Cert_AveMariaRAT_Sectigo_0690EE21E99B1CB3B599BBA7B9262CDC {
   meta:
      description         = "Detects AveMariaRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-06-20"
      version             = "1.0"

      hash                = "e6042f28df9d2c4a7f7adae1ad8ce6f6f44982e19db58463badb3a49d516eab4"
      malware             = "AveMariaRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Tongbu Networks Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "06:90:ee:21:e9:9b:1c:b3:b5:99:bb:a7:b9:26:2c:dc"
      cert_thumbprint     = "FF9A35EF5865024E49096672AB941B5C120657B9"
      cert_valid_from     = "2019-06-20"
      cert_valid_to       = "2022-06-19"

      country             = "CN"
      state               = "xiamen"
      locality            = "xiamen"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "06:90:ee:21:e9:9b:1c:b3:b5:99:bb:a7:b9:26:2c:dc"
      )
}
