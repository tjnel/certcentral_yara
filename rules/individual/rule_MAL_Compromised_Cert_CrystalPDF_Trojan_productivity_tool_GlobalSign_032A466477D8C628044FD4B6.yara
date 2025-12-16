import "pe"

rule MAL_Compromised_Cert_CrystalPDF_Trojan_productivity_tool_GlobalSign_032A466477D8C628044FD4B6 {
   meta:
      description         = "Detects CrystalPDF,Trojan productivity tool with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-26"
      version             = "1.0"

      hash                = "598da788600747cf3fa1f25cb4fa1e029eca1442316709c137690e645a0872bb"
      malware             = "CrystalPDF,Trojan productivity tool"
      malware_type        = "Browser Hijacker"
      malware_notes       = "This software uses obfuscated code to interact with the user's browsers and load unwanted content: https://xcancel.com/struppigel/status/1977691895250772086?s=20"

      signer              = "VAST LAKE LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "03:2a:46:64:77:d8:c6:28:04:4f:d4:b6"
      cert_thumbprint     = "6CDFE03C52808412F8EB6494C5C4DDCE4878DCC8"
      cert_valid_from     = "2025-06-26"
      cert_valid_to       = "2026-06-27"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Herzliya"
      email               = "support@gotovastlake.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "03:2a:46:64:77:d8:c6:28:04:4f:d4:b6"
      )
}
