import "pe"

rule MAL_Compromised_Cert_BuerLoader_Sectigo_009FAF8705A3EAEF9340800CC4FD38597C {
   meta:
      description         = "Detects BuerLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-19"
      version             = "1.0"

      hash                = "242dbfdfe2fb845ea71cf1a04637fe5c3fdfd2f931bd1265040012cd8089ac44"
      malware             = "BuerLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tekhnokod LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
      cert_thumbprint     = "40C572CC19E7CA4C2FB89C96357EFF4C7489958E"
      cert_valid_from     = "2020-11-19"
      cert_valid_to       = "2021-11-19"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
      )
}
