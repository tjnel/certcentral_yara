import "pe"

rule MAL_Compromised_Cert_CrystalPDF_Trojan_productivity_tool_GlobalSign_56ED9A94B87A7231B56F6A02 {
   meta:
      description         = "Detects CrystalPDF, Trojan productivity tool with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-19"
      version             = "1.0"

      hash                = "ac4119cfabf9d29b68ddacb0efdfe9ce555fc0569327e102094a45a6c1cf23cb"
      malware             = "CrystalPDF, Trojan productivity tool"
      malware_type        = "Browser Hijacker"
      malware_notes       = "This software uses obfuscated code to interact with the user's browsers and load unwanted content: https://xcancel.com/struppigel/status/1977691895250772086?s=20"

      signer              = "LONG SOUND LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:ed:9a:94:b8:7a:72:31:b5:6f:6a:02"
      cert_thumbprint     = "ECE7440C53C235E5E69E57EACB9250154AF20DE0"
      cert_valid_from     = "2024-09-19"
      cert_valid_to       = "2025-09-20"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "support@longsoundltd.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:ed:9a:94:b8:7a:72:31:b5:6f:6a:02"
      )
}
