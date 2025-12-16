import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_5550E7366660417E8F144A5C {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-29"
      version             = "1.0"

      hash                = "a14506c6fb92a5af88a6a44d273edafe10d69ee3d85c8b2a7ac458a22edf68d2"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Ugurmana"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:50:e7:36:66:60:41:7e:8f:14:4a:5c"
      cert_thumbprint     = "94E990D63C112B461F5FDB28D3A9B27675A64480"
      cert_valid_from     = "2025-05-29"
      cert_valid_to       = "2026-05-30"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1187847189628"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:50:e7:36:66:60:41:7e:8f:14:4a:5c"
      )
}
