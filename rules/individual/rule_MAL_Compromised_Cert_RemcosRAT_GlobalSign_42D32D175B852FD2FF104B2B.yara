import "pe"

rule MAL_Compromised_Cert_RemcosRAT_GlobalSign_42D32D175B852FD2FF104B2B {
   meta:
      description         = "Detects RemcosRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-23"
      version             = "1.0"

      hash                = "07b05ce1a411871e69f2c93b636659b677fcb545b4c05b6641d362b04138704f"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MILIO LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:d3:2d:17:5b:85:2f:d2:ff:10:4b:2b"
      cert_thumbprint     = "32145EE7FD51879BB6507CF6975A0EA43973BFF8"
      cert_valid_from     = "2025-03-23"
      cert_valid_to       = "2026-02-20"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:d3:2d:17:5b:85:2f:d2:ff:10:4b:2b"
      )
}
