import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_5D00264A6B804AE6B28D9B16 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-10"
      version             = "1.0"

      hash                = "9d5c551f076449af0dbd7e05e1c2e439d6f6335b3dd07a8fa1b819c250327f39"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "LLC YUSAL"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:00:26:4a:6b:80:4a:e6:b2:8d:9b:16"
      cert_thumbprint     = "7a6de7caed669a318bb7507755d5b4685a8f89ff94ee5cb6ea4d77e18a1fc1c9"
      cert_valid_from     = "2025-01-10"
      cert_valid_to       = "2026-01-11"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1196313074726"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:00:26:4a:6b:80:4a:e6:b2:8d:9b:16"
      )
}
