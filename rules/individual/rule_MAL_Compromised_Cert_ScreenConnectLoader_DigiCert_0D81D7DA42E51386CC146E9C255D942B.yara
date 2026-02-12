import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_DigiCert_0D81D7DA42E51386CC146E9C255D942B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-05"
      version             = "1.0"

      hash                = "60d40df5336eadff150590b25c72183e6f4a0d3bb7733bb7d1929b86b1ea2d65"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "The screenconnect instance connects to boriserton27[.]anondns[.]net"

      signer              = "XRYUS TECHNOLOGIES LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:81:d7:da:42:e5:13:86:cc:14:6e:9c:25:5d:94:2b"
      cert_thumbprint     = "F970B0B2F1DE85E3F629AEA579C9A57FE9330A61"
      cert_valid_from     = "2025-12-05"
      cert_valid_to       = "2026-12-04"

      country             = "JP"
      state               = "Tokyo"
      locality            = "Minato-ku"
      email               = "???"
      rdn_serial_number   = "2900-01-095356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:81:d7:da:42:e5:13:86:cc:14:6e:9c:25:5d:94:2b"
      )
}
