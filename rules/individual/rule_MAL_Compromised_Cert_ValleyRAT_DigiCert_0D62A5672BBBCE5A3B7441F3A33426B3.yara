import "pe"

rule MAL_Compromised_Cert_ValleyRAT_DigiCert_0D62A5672BBBCE5A3B7441F3A33426B3 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "3f78ec4bd0a0ccff1c5e0fda4f47531abb343a9835682c40f538bebab5b770e8"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "咸宁创翼互联网科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:62:a5:67:2b:bb:ce:5a:3b:74:41:f3:a3:34:26:b3"
      cert_thumbprint     = "64FEDDCC08A4EA49D603262FA1B2750695A03A18"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2025-08-13"

      country             = "CN"
      state               = "湖北省"
      locality            = "咸宁市"
      email               = "???"
      rdn_serial_number   = "91422300MAEA9BX51L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:62:a5:67:2b:bb:ce:5a:3b:74:41:f3:a3:34:26:b3"
      )
}
