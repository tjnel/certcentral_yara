import "pe"

rule MAL_Compromised_Cert_Baoloader_DigiCert_0DEFC375DC6DCDAED0CE4B249127755A {
   meta:
      description         = "Detects Baoloader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-01"
      version             = "1.0"

      hash                = "b9b4375c1992b71f9dc08ee613b2b316b8df8b9e1fdd2c7a1e98d89f43a1625f"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Summit Nexus Holdings LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:ef:c3:75:dc:6d:cd:ae:d0:ce:4b:24:91:27:75:5a"
      cert_thumbprint     = "76C675514EEC3A27A4E551A77ED30FBB0DC43A01"
      cert_valid_from     = "2025-08-01"
      cert_valid_to       = "2026-07-31"

      country             = "US"
      state               = "Wyoming"
      locality            = "Sheridan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:ef:c3:75:dc:6d:cd:ae:d0:ce:4b:24:91:27:75:5a"
      )
}
