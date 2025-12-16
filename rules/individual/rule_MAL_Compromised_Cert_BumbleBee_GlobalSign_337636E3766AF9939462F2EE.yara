import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_337636E3766AF9939462F2EE {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "839e3f4dc441578019dc33c43bc918ad7e6022baa3770f45c6eccfe1239d79c1"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Ellada Comfort"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "33:76:36:e3:76:6a:f9:93:94:62:f2:ee"
      cert_thumbprint     = "A6EB7DD1D55FFE0B5FA1567E8AA23D279C56D832"
      cert_valid_from     = "2025-04-24"
      cert_valid_to       = "2026-04-25"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1217700501457"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "33:76:36:e3:76:6a:f9:93:94:62:f2:ee"
      )
}
