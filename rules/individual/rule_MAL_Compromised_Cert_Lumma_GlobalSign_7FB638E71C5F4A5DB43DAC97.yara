import "pe"

rule MAL_Compromised_Cert_Lumma_GlobalSign_7FB638E71C5F4A5DB43DAC97 {
   meta:
      description         = "Detects Lumma with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-28"
      version             = "1.0"

      hash                = "1d881f83f82d4393e96d206145f35ccaf695380dc05d99a8eae9b2a001e04b13"
      malware             = "Lumma"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "SLS Immobilien und Beteiligungs GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:b6:38:e7:1c:5f:4a:5d:b4:3d:ac:97"
      cert_thumbprint     = "05AE3873EC1B92235BB7A99A04CD2D06E2C8B815"
      cert_valid_from     = "2025-03-28"
      cert_valid_to       = "2026-03-29"

      country             = "AT"
      state               = "Niederoesterreich"
      locality            = "Ebreichsdorf"
      email               = "???"
      rdn_serial_number   = "632119m"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:b6:38:e7:1c:5f:4a:5d:b4:3d:ac:97"
      )
}
