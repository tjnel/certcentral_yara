import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_00DE34D4760FCACCE429A83C05E8167607 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-27"
      version             = "1.0"

      hash                = "31373f9fa6608dc5f5ebeae69ef28d819e52d0d13d5e83ca84e7326bf627a220"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HAM AND FIRKIN LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:de:34:d4:76:0f:ca:cc:e4:29:a8:3c:05:e8:16:76:07"
      cert_thumbprint     = "C5DE774A0D0C50D008CDBB1174AA9E2E90A183AF"
      cert_valid_from     = "2025-10-27"
      cert_valid_to       = "2026-10-27"

      country             = "GB"
      state               = "North Yorkshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "13587632"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:de:34:d4:76:0f:ca:cc:e4:29:a8:3c:05:e8:16:76:07"
      )
}
