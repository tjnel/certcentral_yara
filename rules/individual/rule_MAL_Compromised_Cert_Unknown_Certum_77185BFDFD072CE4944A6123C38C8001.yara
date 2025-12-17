import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_77185BFDFD072CE4944A6123C38C8001 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-08"
      version             = "1.0"

      hash                = "99f8878d408857acbba11b04d6c21153368f121fd572e0eaed1ec4823955f6e9"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chongqing Feide Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "77:18:5b:fd:fd:07:2c:e4:94:4a:61:23:c3:8c:80:01"
      cert_thumbprint     = "0BED5FE3BDC1ED5EB41F97E2F30E94884D4A596D"
      cert_valid_from     = "2025-02-08"
      cert_valid_to       = "2026-02-08"

      country             = "CN"
      state               = "Chongqing"
      locality            = "Chongqing"
      email               = "???"
      rdn_serial_number   = "91500118MA613XPC26"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "77:18:5b:fd:fd:07:2c:e4:94:4a:61:23:c3:8c:80:01"
      )
}
