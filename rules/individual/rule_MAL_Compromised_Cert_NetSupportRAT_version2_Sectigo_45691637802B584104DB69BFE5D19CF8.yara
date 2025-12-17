import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_version2_Sectigo_45691637802B584104DB69BFE5D19CF8 {
   meta:
      description         = "Detects NetSupportRAT_version2 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-11"
      version             = "1.0"

      hash                = "027ecb49da01452f5a573f3c2a67ec2d64a851f487da05aca4de6c46955552d3"
      malware             = "NetSupportRAT_version2"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "TWO PILOTS DOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "45:69:16:37:80:2b:58:41:04:db:69:bf:e5:d1:9c:f8"
      cert_thumbprint     = "273786A315BEA0FB02D26EFDEAF83C17BD878A00"
      cert_valid_from     = "2020-09-11"
      cert_valid_to       = "2023-09-12"

      country             = "RS"
      state               = "???"
      locality            = "BELGRADE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "45:69:16:37:80:2b:58:41:04:db:69:bf:e5:d1:9c:f8"
      )
}
