import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_39FCEC85A551B9F9302D7D6B5ACA8E88 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-12"
      version             = "1.0"

      hash                = "b9cea251e74bcf2d7bb7d3d587ad9ac548178a35ec1479e3c60936c914f6d5c3"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "PLUS PAY SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "39:fc:ec:85:a5:51:b9:f9:30:2d:7d:6b:5a:ca:8e:88"
      cert_thumbprint     = "EB841B06EB0E6E1EB729E0879C3C913F6305FA6A"
      cert_valid_from     = "2024-01-12"
      cert_valid_to       = "2025-01-11"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000818204"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "39:fc:ec:85:a5:51:b9:f9:30:2d:7d:6b:5a:ca:8e:88"
      )
}
