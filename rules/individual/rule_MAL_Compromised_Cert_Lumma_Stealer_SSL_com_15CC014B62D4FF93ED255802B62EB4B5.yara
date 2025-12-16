import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_15CC014B62D4FF93ED255802B62EB4B5 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-18"
      version             = "1.0"

      hash                = "3d5768d3ee28635799dc2140011a9ef70c95e76fce2ab09d953c93a3c3db8d9c"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Business Account Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:cc:01:4b:62:d4:ff:93:ed:25:58:02:b6:2e:b4:b5"
      cert_thumbprint     = "A04B08220EF5B92A5A76F4A85B38BBE8893F2A73"
      cert_valid_from     = "2024-03-18"
      cert_valid_to       = "2025-02-26"

      country             = "GB"
      state               = "England"
      locality            = "Ipswich"
      email               = "???"
      rdn_serial_number   = "14748270"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:cc:01:4b:62:d4:ff:93:ed:25:58:02:b6:2e:b4:b5"
      )
}
