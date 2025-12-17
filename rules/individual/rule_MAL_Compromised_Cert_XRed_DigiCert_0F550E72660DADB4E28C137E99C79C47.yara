import "pe"

rule MAL_Compromised_Cert_XRed_DigiCert_0F550E72660DADB4E28C137E99C79C47 {
   meta:
      description         = "Detects XRed with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-22"
      version             = "1.0"

      hash                = "87d8965e3236ee05e583f98b2888baf145c5276975feac5868a5a904b0a820e4"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "深圳市志仕智能科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0f:55:0e:72:66:0d:ad:b4:e2:8c:13:7e:99:c7:9c:47"
      cert_thumbprint     = "BE0BC9065321A3AD4DCA60DA13FF66FC8467FFB5"
      cert_valid_from     = "2025-05-22"
      cert_valid_to       = "2026-05-21"

      country             = "CN"
      state               = "广东省"
      locality            = "深圳市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0f:55:0e:72:66:0d:ad:b4:e2:8c:13:7e:99:c7:9c:47"
      )
}
