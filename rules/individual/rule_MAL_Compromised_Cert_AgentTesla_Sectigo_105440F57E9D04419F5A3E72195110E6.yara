import "pe"

rule MAL_Compromised_Cert_AgentTesla_Sectigo_105440F57E9D04419F5A3E72195110E6 {
   meta:
      description         = "Detects AgentTesla with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2019-10-17"
      version             = "1.0"

      hash                = "5c276ccc993a6b068a9ba8c9f3bcd2ea8f8a8d88c318991108696b41c35d3a86"
      malware             = "AgentTesla"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CRYPTOLAYER SRL"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6"
      cert_thumbprint     = "5CDB3DEB4B2D41AAEAF5E840C41CD685A15CF33A"
      cert_valid_from     = "2019-10-17"
      cert_valid_to       = "2021-10-16"

      country             = "RO"
      state               = "Sibiu"
      locality            = "Sibiu"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6"
      )
}
