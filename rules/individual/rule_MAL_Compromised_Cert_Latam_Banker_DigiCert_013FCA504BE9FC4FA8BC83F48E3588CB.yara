import "pe"

rule MAL_Compromised_Cert_Latam_Banker_DigiCert_013FCA504BE9FC4FA8BC83F48E3588CB {
   meta:
      description         = "Detects Latam Banker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-06"
      version             = "1.0"

      hash                = "1accf8d0d6a0d99b624236f815c3344e9d0509fb136a47b455b35694ebb4e3ea"
      malware             = "Latam Banker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PROTECNOLOGY SOFT LTDA"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:3f:ca:50:4b:e9:fc:4f:a8:bc:83:f4:8e:35:88:cb"
      cert_thumbprint     = "D16A464CE42F1C7A679A63C33D5D3BD8D507C73A"
      cert_valid_from     = "2025-02-06"
      cert_valid_to       = "2026-02-05"

      country             = "BR"
      state               = "Maranhao"
      locality            = "SAO LUIS"
      email               = "???"
      rdn_serial_number   = "17.205.193/0001-10"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:3f:ca:50:4b:e9:fc:4f:a8:bc:83:f4:8e:35:88:cb"
      )
}
