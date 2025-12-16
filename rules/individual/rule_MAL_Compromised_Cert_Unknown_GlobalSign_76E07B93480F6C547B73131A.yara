import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_76E07B93480F6C547B73131A {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-25"
      version             = "1.0"

      hash                = "43c102f2db55c353e0e24fdc0e6c935093de02162e7b564f0881453058a0fdcc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Instrtekhsnab"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "76:e0:7b:93:48:0f:6c:54:7b:73:13:1a"
      cert_thumbprint     = "9B22B51674EA7B78797B66B78C64089BFC35F9A7"
      cert_valid_from     = "2025-03-25"
      cert_valid_to       = "2026-03-26"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Lyubertsy"
      email               = "???"
      rdn_serial_number   = "1165027060241"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "76:e0:7b:93:48:0f:6c:54:7b:73:13:1a"
      )
}
