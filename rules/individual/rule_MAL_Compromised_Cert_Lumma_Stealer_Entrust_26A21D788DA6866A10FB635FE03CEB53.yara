import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Entrust_26A21D788DA6866A10FB635FE03CEB53 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-19"
      version             = "1.0"

      hash                = "9bd25e01ae96fb8c0e3672f32bbe8f39db4099133ddceaaa87c7d74258d8ed1f"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Software Support ApS"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "26:a2:1d:78:8d:a6:86:6a:10:fb:63:5f:e0:3c:eb:53"
      cert_thumbprint     = "765B61077F49F2D2F275D942203B67A8AAC76D2C"
      cert_valid_from     = "2024-10-19"
      cert_valid_to       = "2025-10-19"

      country             = "DK"
      state               = "???"
      locality            = "København N"
      email               = "???"
      rdn_serial_number   = "37790672"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "26:a2:1d:78:8d:a6:86:6a:10:fb:63:5f:e0:3c:eb:53"
      )
}
