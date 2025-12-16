import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_DigiCert_0C84D1A66AA31C56A7627A7B2CA71E32 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-31"
      version             = "1.0"

      hash                = "692159db6232a1a7e791ba171b5ff9f18b7e3c85f0a86dc1d71af04fbaad1000"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "REC EXPERT LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:84:d1:a6:6a:a3:1c:56:a7:62:7a:7b:2c:a7:1e:32"
      cert_thumbprint     = "6DDF35C8300B5203E0ABF930947AB86FA7844128"
      cert_valid_from     = "2024-10-31"
      cert_valid_to       = "2025-10-30"

      country             = "GB"
      state               = "???"
      locality            = "Uxbridge"
      email               = "???"
      rdn_serial_number   = "11926625"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:84:d1:a6:6a:a3:1c:56:a7:62:7a:7b:2c:a7:1e:32"
      )
}
