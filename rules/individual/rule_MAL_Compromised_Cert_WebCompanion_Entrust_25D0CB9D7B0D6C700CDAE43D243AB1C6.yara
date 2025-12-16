import "pe"

rule MAL_Compromised_Cert_WebCompanion_Entrust_25D0CB9D7B0D6C700CDAE43D243AB1C6 {
   meta:
      description         = "Detects WebCompanion with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-01"
      version             = "1.0"

      hash                = "38b605a45b286c4827327bc6e10d08afc71e5dd8d2c9b4f717b1d8039e0f92c8"
      malware             = "WebCompanion"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "7270356 Canada Inc."
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "25:d0:cb:9d:7b:0d:6c:70:0c:da:e4:3d:24:3a:b1:c6"
      cert_thumbprint     = "EA06433E6F12D2AADA040F4A6EF7C927404A4CBA"
      cert_valid_from     = "2024-05-01"
      cert_valid_to       = "2025-05-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "25:d0:cb:9d:7b:0d:6c:70:0c:da:e4:3d:24:3a:b1:c6"
      )
}
