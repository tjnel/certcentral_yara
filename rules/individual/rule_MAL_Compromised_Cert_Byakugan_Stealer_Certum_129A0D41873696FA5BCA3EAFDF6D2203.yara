import "pe"

rule MAL_Compromised_Cert_Byakugan_Stealer_Certum_129A0D41873696FA5BCA3EAFDF6D2203 {
   meta:
      description         = "Detects Byakugan Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "2aa216ed196aa8f75c21d27f64a0c78ec28a967c0fe5b5140e74295d3f316187"
      malware             = "Byakugan Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sichuan Youyixing Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "12:9a:0d:41:87:36:96:fa:5b:ca:3e:af:df:6d:22:03"
      cert_thumbprint     = "8834CB5377A3E6D4140253B5576F677D36981374"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-28"

      country             = "CN"
      state               = "四川省"
      locality            = "成都市"
      email               = "???"
      rdn_serial_number   = "91510100MADJ6CPP7M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "12:9a:0d:41:87:36:96:fa:5b:ca:3e:af:df:6d:22:03"
      )
}
