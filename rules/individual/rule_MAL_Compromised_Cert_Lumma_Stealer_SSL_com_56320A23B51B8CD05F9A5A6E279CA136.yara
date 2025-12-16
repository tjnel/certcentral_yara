import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_56320A23B51B8CD05F9A5A6E279CA136 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-10"
      version             = "1.0"

      hash                = "f1ad63f121b6228bbf88b7b933fbdb4a32ebd7311ea732d4eab38c2d627bfbfe"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "ACCU Technical s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "56:32:0a:23:b5:1b:8c:d0:5f:9a:5a:6e:27:9c:a1:36"
      cert_thumbprint     = "66327EDA391A6F1D2DAECEB204AA533C80604756"
      cert_valid_from     = "2024-01-10"
      cert_valid_to       = "2025-01-09"

      country             = "SK"
      state               = "Trnava Region"
      locality            = "Galanta"
      email               = "???"
      rdn_serial_number   = "51 078 104"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "56:32:0a:23:b5:1b:8c:d0:5f:9a:5a:6e:27:9c:a1:36"
      )
}
