import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0497D45997C350D2867A7764017C3F3F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-02"
      version             = "1.0"

      hash                = "d62dfb0d94b292d6fbedbe98757e796f886c32e8d29d347b7b0cee06e863fccb"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Eugene Investment & Securities Co.,Ltd"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "04:97:d4:59:97:c3:50:d2:86:7a:77:64:01:7c:3f:3f"
      cert_thumbprint     = "9CB771C734F6C0BF6371B2B2E7B1C3C494DA6FAD"
      cert_valid_from     = "2023-05-02"
      cert_valid_to       = "2026-05-04"

      country             = "KR"
      state               = "Seoul"
      locality            = "Yeongdeungpo-gu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "04:97:d4:59:97:c3:50:d2:86:7a:77:64:01:7c:3f:3f"
      )
}
