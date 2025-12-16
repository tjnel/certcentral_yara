import "pe"

rule MAL_Compromised_Cert_AureliaLoader_GlobalSign_34C0A364310AAAC36D86BA98 {
   meta:
      description         = "Detects AureliaLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-17"
      version             = "1.0"

      hash                = "bd7807e61b565751f8d1df788a531d988e5d2054b61ede073e6fc9c237d9e730"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UBUNTU CHEFS (PTY) LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:c0:a3:64:31:0a:aa:c3:6d:86:ba:98"
      cert_thumbprint     = "66A466471DE70A652C287118AE6DE1FA90B57613"
      cert_valid_from     = "2025-06-17"
      cert_valid_to       = "2026-06-18"

      country             = "ZA"
      state               = "Gauteng"
      locality            = "Bryanston"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:c0:a3:64:31:0a:aa:c3:6d:86:ba:98"
      )
}
