import "pe"

rule MAL_Compromised_Cert_Xworm_Certum_2D62E539DA36F1532DEC45AF6D991A09 {
   meta:
      description         = "Detects Xworm with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-26"
      version             = "1.0"

      hash                = "307b77d2b1e2f81de47851567840a0b44e53ac74b9ad2c0c9aa91228e8581aab"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "珠海康晶科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2d:62:e5:39:da:36:f1:53:2d:ec:45:af:6d:99:1a:09"
      cert_thumbprint     = "ABBF9EEBE893B9EC0B5F9664589D0202444784D5"
      cert_valid_from     = "2024-04-26"
      cert_valid_to       = "2025-04-26"

      country             = "CN"
      state               = "广东"
      locality            = "珠海"
      email               = "???"
      rdn_serial_number   = "91440400MA55GU3W0F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2d:62:e5:39:da:36:f1:53:2d:ec:45:af:6d:99:1a:09"
      )
}
