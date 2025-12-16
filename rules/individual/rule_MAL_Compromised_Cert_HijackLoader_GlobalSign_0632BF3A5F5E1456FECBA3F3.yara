import "pe"

rule MAL_Compromised_Cert_HijackLoader_GlobalSign_0632BF3A5F5E1456FECBA3F3 {
   meta:
      description         = "Detects HijackLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-20"
      version             = "1.0"

      hash                = "60972229523eb137860bae114a667ace6d6109ebeec4f219628cdfe00e88d145"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Stroy-Klining"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "06:32:bf:3a:5f:5e:14:56:fe:cb:a3:f3"
      cert_thumbprint     = "DE1C9D957BAEF17EC47BB9AD236E9049E0DE9ED8"
      cert_valid_from     = "2025-05-20"
      cert_valid_to       = "2026-05-21"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1207700373583"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "06:32:bf:3a:5f:5e:14:56:fe:cb:a3:f3"
      )
}
