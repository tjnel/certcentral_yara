import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_4FB69AAF484B6AB16D120318552ABC33 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "9eef7a5dd156e3c63fef452f69cd04070a8856e49fc85d58a18664be48360a63"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangzhou Haotu Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4f:b6:9a:af:48:4b:6a:b1:6d:12:03:18:55:2a:bc:33"
      cert_thumbprint     = "DAE4E5B747145F968824A542D5FB946E386DA7F2"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-24"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "913301063283021923"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4f:b6:9a:af:48:4b:6a:b1:6d:12:03:18:55:2a:bc:33"
      )
}
