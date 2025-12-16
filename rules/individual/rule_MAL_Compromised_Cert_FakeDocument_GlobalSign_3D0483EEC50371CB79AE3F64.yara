import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_3D0483EEC50371CB79AE3F64 {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-24"
      version             = "1.0"

      hash                = "974f987b80129596083b764db7d64291790e176bb56c3de6412b27018264e45f"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VEDAPRIME BIO CARE LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3d:04:83:ee:c5:03:71:cb:79:ae:3f:64"
      cert_thumbprint     = "0A0639315552778DE838C7238ABD909B6BDAB9DE"
      cert_valid_from     = "2025-06-24"
      cert_valid_to       = "2026-06-25"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "shankarvedabio@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3d:04:83:ee:c5:03:71:cb:79:ae:3f:64"
      )
}
