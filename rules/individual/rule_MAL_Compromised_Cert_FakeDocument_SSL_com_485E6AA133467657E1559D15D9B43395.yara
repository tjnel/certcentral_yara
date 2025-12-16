import "pe"

rule MAL_Compromised_Cert_FakeDocument_SSL_com_485E6AA133467657E1559D15D9B43395 {
   meta:
      description         = "Detects FakeDocument with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-18"
      version             = "1.0"

      hash                = "457ac982abd3d09b639b21b7ebf4f702e39aab3de4b61aac6e28cd962404846f"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "West Software Pty Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "48:5e:6a:a1:33:46:76:57:e1:55:9d:15:d9:b4:33:95"
      cert_thumbprint     = "FA3ED8E49FB853CBB172AE16B9C3B296394821CC"
      cert_valid_from     = "2025-09-18"
      cert_valid_to       = "2026-09-18"

      country             = "AU"
      state               = "Western Australia"
      locality            = "Kenwick"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "48:5e:6a:a1:33:46:76:57:e1:55:9d:15:d9:b4:33:95"
      )
}
