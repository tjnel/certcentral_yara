import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Entrust_0B64E71114288245604A4474A5B9374D {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-31"
      version             = "1.0"

      hash                = "ec3ec6568b2f15f13b7316416fc6354c33bb02f253cb91d507fab4bd6e743f71"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Software Support ApS"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "0b:64:e7:11:14:28:82:45:60:4a:44:74:a5:b9:37:4d"
      cert_thumbprint     = "3D97A8146CF34E2FC8AD8418B16C4B4B68E3C526"
      cert_valid_from     = "2024-07-31"
      cert_valid_to       = "2025-07-31"

      country             = "DK"
      state               = "???"
      locality            = "København N"
      email               = "???"
      rdn_serial_number   = "37790672"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "0b:64:e7:11:14:28:82:45:60:4a:44:74:a5:b9:37:4d"
      )
}
