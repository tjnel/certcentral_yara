import "pe"

rule MAL_Compromised_Cert_Meterpreter_DigiCert_03B50181EBBAD1AB42C7D901FB1A932A {
   meta:
      description         = "Detects Meterpreter with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-17"
      version             = "1.0"

      hash                = "5dda81c4f51a5189adc50e8943d6e6849f0538898552a41caa7cf6ad9585cd18"
      malware             = "Meterpreter"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "優勢領航科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:b5:01:81:eb:ba:d1:ab:42:c7:d9:01:fb:1a:93:2a"
      cert_thumbprint     = "C40DE237745620CA2583ADF850D1540262EE439B"
      cert_valid_from     = "2023-05-17"
      cert_valid_to       = "2026-05-17"

      country             = "TW"
      state               = "台北市"
      locality            = "大安区"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:b5:01:81:eb:ba:d1:ab:42:c7:d9:01:fb:1a:93:2a"
      )
}
