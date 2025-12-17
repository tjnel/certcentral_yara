import "pe"

rule MAL_Compromised_Cert_FakeAdvancedIPScanner_GlobalSign_23CA2FC2A588B52B7D70E96B {
   meta:
      description         = "Detects FakeAdvancedIPScanner with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "05d2d06143d363c1e41546f14c1d99b082402460ba4e8598667614de996d2fbc"
      malware             = "FakeAdvancedIPScanner"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ANVIA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:ca:2f:c2:a5:88:b5:2b:7d:70:e9:6b"
      cert_thumbprint     = "6CBC820B354C4712EEB55A8CD8AB6ECCB9BA4D21"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-06-24"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:ca:2f:c2:a5:88:b5:2b:7d:70:e9:6b"
      )
}
