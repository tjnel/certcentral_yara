import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_Team_GlobalSign_25866F3E001AC42FBBE8C679 {
   meta:
      description         = "Detects Wagmi Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-31"
      version             = "1.0"

      hash                = "f08cafea466576fb980b2d4729234a94258343ce40412ba45cd391fcf7773c68"
      malware             = "Wagmi Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ZONALS COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "25:86:6f:3e:00:1a:c4:2f:bb:e8:c6:79"
      cert_thumbprint     = "28921D40E2EFE51D8B1C9891ED0B72AEE137327A"
      cert_valid_from     = "2025-03-31"
      cert_valid_to       = "2026-04-01"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "C.151394"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "25:86:6f:3e:00:1a:c4:2f:bb:e8:c6:79"
      )
}
