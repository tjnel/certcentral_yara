import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_7A72DDC4BCA8E1D810B258B3 {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-30"
      version             = "1.0"

      hash                = "9b9c91e22566b658bcfefc8c463c74934d9bb5585b4516173407ba7f8ae9863a"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Jinyuan Qiming Network Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7a:72:dd:c4:bc:a8:e1:d8:10:b2:58:b3"
      cert_thumbprint     = "2D510C174453E38F5541161A77966DDECB042AF2"
      cert_valid_from     = "2025-06-30"
      cert_valid_to       = "2026-07-01"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7a:72:dd:c4:bc:a8:e1:d8:10:b2:58:b3"
      )
}
