import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_410DCFAE3DB2E499FD92C563 {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-11"
      version             = "1.0"

      hash                = "80c8a6ecd5619d137aa57ddf252ab5dc9044266fca87f3e90c5b7f3664c5142f"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "PROFTORG LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:0d:cf:ae:3d:b2:e4:99:fd:92:c5:63"
      cert_thumbprint     = "D8F9AD4881FAEDF9B2EB4983C321FF499DCB931F"
      cert_valid_from     = "2025-06-11"
      cert_valid_to       = "2026-06-12"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "proftorg.info@rambler.ru"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:0d:cf:ae:3d:b2:e4:99:fd:92:c5:63"
      )
}
