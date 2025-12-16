import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7E9E39FE8C3639878172F97D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "1a24a12722da65ccf119dccb51aceb1eff49de9c49310d0c7af6746b43721fec"
      malware             = "Unknown"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware launches a web browser with ChatGPT as a decoy. The malware itself pretends to be a \"GPTAI installer\" and sets a scheduled task called \"GPTAI Update Scheduler\". The malware is unknown but appears related to b89bef3b118ba3fb9261962eaee144525ee4c5a109f5817d9172cb6e67129b42 which was a fake Notepad++ installer."

      signer              = "SIA “WASD”"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:9e:39:fe:8c:36:39:87:81:72:f9:7d"
      cert_thumbprint     = "D1758376E69CFE20F4B92D66189292D4E45C625A"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-29"

      country             = "LV"
      state               = "Riga"
      locality            = "Riga"
      email               = "???"
      rdn_serial_number   = "42103107631"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:9e:39:fe:8c:36:39:87:81:72:f9:7d"
      )
}
