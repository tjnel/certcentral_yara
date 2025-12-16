import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_19941067ECDF1AEE6337ABA743515E41 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-02"
      version             = "1.0"

      hash                = "1eacc8604c24976d62cb1af56a1e9bcac70d738fa8fcbe1067364ad7ff90546b"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Kslugidea Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "19:94:10:67:ec:df:1a:ee:63:37:ab:a7:43:51:5e:41"
      cert_thumbprint     = "3F9B93E7C83302442D72733A5A4B97124308EFFF"
      cert_valid_from     = "2024-08-02"
      cert_valid_to       = "2025-08-02"

      country             = "GB"
      state               = "???"
      locality            = "Wembley"
      email               = "???"
      rdn_serial_number   = "12378927"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "19:94:10:67:ec:df:1a:ee:63:37:ab:a7:43:51:5e:41"
      )
}
