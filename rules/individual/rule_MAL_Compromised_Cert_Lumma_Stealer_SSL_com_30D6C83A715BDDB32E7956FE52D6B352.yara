import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_30D6C83A715BDDB32E7956FE52D6B352 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-03"
      version             = "1.0"

      hash                = "afdc1a1e1e934f18be28465315704a12b2cd43c186fbee94f7464392849a5ad0"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "ConsolHQ LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "30:d6:c8:3a:71:5b:dd:b3:2e:79:56:fe:52:d6:b3:52"
      cert_thumbprint     = "07728484B1BB8702A87C6E5A154E0D690AF2FF38"
      cert_valid_from     = "2024-12-03"
      cert_valid_to       = "2025-08-30"

      country             = "GB"
      state               = "???"
      locality            = "Erith"
      email               = "???"
      rdn_serial_number   = "12800651"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "30:d6:c8:3a:71:5b:dd:b3:2e:79:56:fe:52:d6:b3:52"
      )
}
