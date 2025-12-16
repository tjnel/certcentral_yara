import "pe"

rule MAL_Compromised_Cert_oyster_GlobalSign_7C75A58852CA4C72348CF24D {
   meta:
      description         = "Detects oyster with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-04"
      version             = "1.0"

      hash                = "eef6d4b6bdf48a605cade0b517d5a51fc4f4570e505f3d8b9b66158902dcd4af"
      malware             = "oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Bravery"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:75:a5:88:52:ca:4c:72:34:8c:f2:4d"
      cert_thumbprint     = "FB85AA1E12C09130035D3EB72B50EBF5CCE092C7"
      cert_valid_from     = "2025-07-04"
      cert_valid_to       = "2026-07-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1226100007077"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:75:a5:88:52:ca:4c:72:34:8c:f2:4d"
      )
}
