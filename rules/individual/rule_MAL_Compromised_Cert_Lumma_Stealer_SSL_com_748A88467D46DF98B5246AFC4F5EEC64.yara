import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_748A88467D46DF98B5246AFC4F5EEC64 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-15"
      version             = "1.0"

      hash                = "649ec4858e572e0145e35a9faa712708949b7bb1bce1594154cda580d80a0ca9"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Acira Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "74:8a:88:46:7d:46:df:98:b5:24:6a:fc:4f:5e:ec:64"
      cert_thumbprint     = "A70AB688FF0A7C3A22B030FBFFA8B56DC31F650A"
      cert_valid_from     = "2024-01-15"
      cert_valid_to       = "2025-01-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "987024-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "74:8a:88:46:7d:46:df:98:b5:24:6a:fc:4f:5e:ec:64"
      )
}
