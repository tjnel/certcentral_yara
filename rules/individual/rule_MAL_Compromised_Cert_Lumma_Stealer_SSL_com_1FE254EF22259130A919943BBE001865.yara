import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_1FE254EF22259130A919943BBE001865 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-07"
      version             = "1.0"

      hash                = "33d80d826bcc36c44603e065547e1038e94478d4053c31eb472d4f159d2964f4"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Scarcroft Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1f:e2:54:ef:22:25:91:30:a9:19:94:3b:be:00:18:65"
      cert_thumbprint     = "59B94F68B14AA494529030F07130CBBB12892720"
      cert_valid_from     = "2024-08-07"
      cert_valid_to       = "2025-08-07"

      country             = "GB"
      state               = "???"
      locality            = "York"
      email               = "???"
      rdn_serial_number   = "12005238"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1f:e2:54:ef:22:25:91:30:a9:19:94:3b:be:00:18:65"
      )
}
