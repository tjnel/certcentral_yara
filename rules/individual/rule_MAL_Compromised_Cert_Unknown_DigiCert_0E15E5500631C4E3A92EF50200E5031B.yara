import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0E15E5500631C4E3A92EF50200E5031B {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-28"
      version             = "1.0"

      hash                = "576d07cc8919c68914bf08663e0afd00d9f9fbf5263b5cccbded5d373905a296"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "C-DC LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:15:e5:50:06:31:c4:e3:a9:2e:f5:02:00:e5:03:1b"
      cert_thumbprint     = "A6D4E93D8656BAAB2E461E1ACEC6C8E72819AD5A"
      cert_valid_from     = "2024-10-28"
      cert_valid_to       = "2025-10-27"

      country             = "UA"
      state               = "Ivano-Frankivsk Oblast"
      locality            = "Ivano-Frankivsk"
      email               = "???"
      rdn_serial_number   = "42466506"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:15:e5:50:06:31:c4:e3:a9:2e:f5:02:00:e5:03:1b"
      )
}
