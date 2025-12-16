import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_10299E37FC5500D96E41D4E48D171E12 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-01"
      version             = "1.0"

      hash                = "9f21f2f2e295f1b9fef40d70e0f762f508a840a0f9f61928be39628da7dbca11"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "WAGON TRANSPORT LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "10:29:9e:37:fc:55:00:d9:6e:41:d4:e4:8d:17:1e:12"
      cert_thumbprint     = "C25F9BC1E738BBB5D331FA22738B4DFE4B6C6BE2"
      cert_valid_from     = "2024-10-01"
      cert_valid_to       = "2025-10-01"

      country             = "GB"
      state               = "England"
      locality            = "Leicester"
      email               = "???"
      rdn_serial_number   = "06794310"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "10:29:9e:37:fc:55:00:d9:6e:41:d4:e4:8d:17:1e:12"
      )
}
