import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_231078283BAC1A1A90F64202E84177AD {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-16"
      version             = "1.0"

      hash                = "12eae5a374e29ad3ad55c02ca87a53b9cad91a78c000642f719e297852ba0dcc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Zhongxingda Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "23:10:78:28:3b:ac:1a:1a:90:f6:42:02:e8:41:77:ad"
      cert_thumbprint     = "9de58dd588fe6a464c1d21d82033881dd8c176f490838ff5be875e4f862bad8e"
      cert_valid_from     = "2024-12-16"
      cert_valid_to       = "2025-12-16"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5H14K805"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "23:10:78:28:3b:ac:1a:1a:90:f6:42:02:e8:41:77:ad"
      )
}
