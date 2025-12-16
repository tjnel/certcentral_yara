import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_3A9C76F8304F77BD271921D9982F1AB6 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-09"
      version             = "1.0"

      hash                = "87200e8b43a6707cd66fc240d2c9e9da7f3ed03c8507adf7c1cfe56ba1a9c57d"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "SUMMIT RECRUITMENT LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3a:9c:76:f8:30:4f:77:bd:27:19:21:d9:98:2f:1a:b6"
      cert_thumbprint     = "94C21E6384F2FFB72BD856C1C40B788F314B5298"
      cert_valid_from     = "2024-12-09"
      cert_valid_to       = "2025-12-09"

      country             = "GB"
      state               = "???"
      locality            = "Southampton"
      email               = "???"
      rdn_serial_number   = "09304744"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3a:9c:76:f8:30:4f:77:bd:27:19:21:d9:98:2f:1a:b6"
      )
}
