import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_0DB1B701C9F6B3F37385CD38 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-10"
      version             = "1.0"

      hash                = "c229afdd9825d36095c0e0cbaceb2c052d26230cc8a3d453229c69d83d6cf00f"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HORIZON TAX & ACCOUNTING, L.L.C."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0d:b1:b7:01:c9:f6:b3:f3:73:85:cd:38"
      cert_thumbprint     = "0D20A96C9AF631F16C08163ACF894000E1FD325C"
      cert_valid_from     = "2025-07-10"
      cert_valid_to       = "2026-07-11"

      country             = "US"
      state               = "Arizona"
      locality            = "Phoenix"
      email               = "???"
      rdn_serial_number   = "L13325562"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0d:b1:b7:01:c9:f6:b3:f3:73:85:cd:38"
      )
}
