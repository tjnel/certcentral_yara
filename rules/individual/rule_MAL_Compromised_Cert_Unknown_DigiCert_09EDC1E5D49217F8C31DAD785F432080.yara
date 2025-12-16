import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_09EDC1E5D49217F8C31DAD785F432080 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-23"
      version             = "1.0"

      hash                = "03889d0e551959196edef76be880e199ff8d2a2d597c10a1c70ced17f1925b2d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CÔNG TY TNHH DU LỊCH VÀ TỔ CHỨC SỰ KIỆN PROTEAM"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:ed:c1:e5:d4:92:17:f8:c3:1d:ad:78:5f:43:20:80"
      cert_thumbprint     = "53B2E6A6F54837E7F09958FF4254647527684B91"
      cert_valid_from     = "2025-07-23"
      cert_valid_to       = "2026-07-22"

      country             = "VN"
      state               = "Quảng Bình"
      locality            = "Đồng Hới"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:ed:c1:e5:d4:92:17:f8:c3:1d:ad:78:5f:43:20:80"
      )
}
