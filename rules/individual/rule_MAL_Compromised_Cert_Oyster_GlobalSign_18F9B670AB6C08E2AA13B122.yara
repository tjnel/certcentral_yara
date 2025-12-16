import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_18F9B670AB6C08E2AA13B122 {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-07"
      version             = "1.0"

      hash                = "401e3fe6d27a438016a82c4bbc710dfca5ff3c8f533f5eadc7393ce4f1c2d498"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC MCD - Profile"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "18:f9:b6:70:ab:6c:08:e2:aa:13:b1:22"
      cert_thumbprint     = "03C6A12293856EC70A88A91E9DEF3224103B3262"
      cert_valid_from     = "2025-08-07"
      cert_valid_to       = "2026-04-24"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Khimki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "18:f9:b6:70:ab:6c:08:e2:aa:13:b1:22"
      )
}
