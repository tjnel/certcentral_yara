import "pe"

rule MAL_Compromised_Cert_FakeKeypass_Certum_52B05A2A3AD5CAE2946C80F5B621E382 {
   meta:
      description         = "Detects FakeKeypass with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-07"
      version             = "1.0"

      hash                = "2c510f9ae4472342faafb7f2a1f278160f3581ead8ccd5b7ba7951863dcba2f5"
      malware             = "FakeKeypass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Kantianxia Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "52:b0:5a:2a:3a:d5:ca:e2:94:6c:80:f5:b6:21:e3:82"
      cert_thumbprint     = "2CF75DAE1A87CA7962CAF67E7310420BBBC30588"
      cert_valid_from     = "2024-10-07"
      cert_valid_to       = "2025-10-07"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "52:b0:5a:2a:3a:d5:ca:e2:94:6c:80:f5:b6:21:e3:82"
      )
}
