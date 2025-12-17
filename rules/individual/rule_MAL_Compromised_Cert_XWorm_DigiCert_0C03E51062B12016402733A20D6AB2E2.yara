import "pe"

rule MAL_Compromised_Cert_XWorm_DigiCert_0C03E51062B12016402733A20D6AB2E2 {
   meta:
      description         = "Detects XWorm with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-14"
      version             = "1.0"

      hash                = "7fb45016511c46705971d2a3185f805bf7c0b0c7668cd77fae4c46f00d4f8454"
      malware             = "XWorm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RONALDO RODRIGUES SANTANA 22670573878"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:03:e5:10:62:b1:20:16:40:27:33:a2:0d:6a:b2:e2"
      cert_thumbprint     = "c78e08b801eb94a3b70076bb0b5c6a828b7a43c508411e488424ec989cb03799"
      cert_valid_from     = "2024-08-14"
      cert_valid_to       = "2025-08-13"

      country             = "BR"
      state               = "Sao Paulo"
      locality            = "CAMPINAS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:03:e5:10:62:b1:20:16:40:27:33:a2:0d:6a:b2:e2"
      )
}
