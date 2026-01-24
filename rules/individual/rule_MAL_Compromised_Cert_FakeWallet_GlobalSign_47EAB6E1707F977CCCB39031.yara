import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_47EAB6E1707F977CCCB39031 {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-15"
      version             = "1.0"

      hash                = "c1ec42abf050d35a25129b0366346f1871d7bbc720af06547f5fdde6d35e6868"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Fake installer impersonating MultiBIt wallet"

      signer              = "AGRA GYMKHANA CLUB LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:ea:b6:e1:70:7f:97:7c:cc:b3:90:31"
      cert_thumbprint     = "1A6EFAFCB4FA61A9FFBB23A544F50D14A94C86AA"
      cert_valid_from     = "2025-07-15"
      cert_valid_to       = "2026-07-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:ea:b6:e1:70:7f:97:7c:cc:b3:90:31"
      )
}
