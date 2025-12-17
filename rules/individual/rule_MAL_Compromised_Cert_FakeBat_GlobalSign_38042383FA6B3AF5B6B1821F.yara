import "pe"

rule MAL_Compromised_Cert_FakeBat_GlobalSign_38042383FA6B3AF5B6B1821F {
   meta:
      description         = "Detects FakeBat with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-22"
      version             = "1.0"

      hash                = "2020038974f763287b465795b52cba40e6ed533e8d1b67e690a2c88248e99d34"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "KENSO SOFTWARE sp. z o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:04:23:83:fa:6b:3a:f5:b6:b1:82:1f"
      cert_thumbprint     = "CDFA577CE2EC5E0117967D8F65566030B96349A1"
      cert_valid_from     = "2024-04-22"
      cert_valid_to       = "2025-04-23"

      country             = "PL"
      state               = "Województwo podkarpackie"
      locality            = "Rzeszów"
      email               = "admin@kensosoftware.com"
      rdn_serial_number   = "0000897125"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:04:23:83:fa:6b:3a:f5:b6:b1:82:1f"
      )
}
