import "pe"

rule MAL_Compromised_Cert_TrustConnectRMM_Certum_055A00A5DC820FDA8DBB754490B4BACF {
   meta:
      description         = "Detects TrustConnectRMM with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "cf85a4816715b8fa6c1eb5b50d1c70cfef116522742f6f1c77cb8689166b9f40"
      malware             = "TrustConnectRMM"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is being distributed by phishing. The software appears to be designed to be an RMM but is also brand new, all indicators point to malicious."

      signer              = "TrustConnect Software PTY LTD"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "05:5a:00:a5:dc:82:0f:da:8d:bb:75:44:90:b4:ba:cf"
      cert_thumbprint     = "B42F80AD510E0977AFAE672BB86FA8C8CD62E866"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-27"

      country             = "ZA"
      state               = "Gauteng"
      locality            = "Alexandra"
      email               = "???"
      rdn_serial_number   = "2026/029661/07"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "05:5a:00:a5:dc:82:0f:da:8d:bb:75:44:90:b4:ba:cf"
      )
}
