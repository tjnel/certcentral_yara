import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_417B3A9C446891F15B00CAEB70D95CB6 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-26"
      version             = "1.0"

      hash                = "f0434db947410b795adc6a09d0da496ca07edb50ae8af72960d42ac8a89dfa29"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Quanzhou Chunsheng Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "41:7b:3a:9c:44:68:91:f1:5b:00:ca:eb:70:d9:5c:b6"
      cert_thumbprint     = "56856FF8ADE9DD49FD006C6DCF413A4C103DD079"
      cert_valid_from     = "2024-07-26"
      cert_valid_to       = "2025-07-26"

      country             = "CN"
      state               = "Fujian"
      locality            = "Quanzhou"
      email               = "???"
      rdn_serial_number   = "91350582MA8TM0LA3E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "41:7b:3a:9c:44:68:91:f1:5b:00:ca:eb:70:d9:5c:b6"
      )
}
