import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_5762A43579C0117284D1A7EE91D547D4 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-21"
      version             = "1.0"

      hash                = "f0eada6645d7befc0993ebb0ff550019d13bec8bc66d3c479ffacde7d8127d82"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Đoàn Quốc Bảo Khánh"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "57:62:a4:35:79:c0:11:72:84:d1:a7:ee:91:d5:47:d4"
      cert_thumbprint     = "662E0243ADCF201DFF7CFE3665079CD9524CD97C"
      cert_valid_from     = "2025-04-21"
      cert_valid_to       = "2026-04-21"

      country             = "VN"
      state               = "Hà Tĩnh"
      locality            = "Huyện Thạch Hà"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "57:62:a4:35:79:c0:11:72:84:d1:a7:ee:91:d5:47:d4"
      )
}
