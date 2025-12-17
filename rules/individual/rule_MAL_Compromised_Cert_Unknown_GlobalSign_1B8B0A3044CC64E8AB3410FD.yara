import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_1B8B0A3044CC64E8AB3410FD {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-09"
      version             = "1.0"

      hash                = "510edd38e5e6ddd3fa443e05ff539fdbe934883ec31a23378a8893ed6b2c3d76"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHING HANG INFORMATION CO., LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1b:8b:0a:30:44:cc:64:e8:ab:34:10:fd"
      cert_thumbprint     = "295AE7B270230F8072862CCAF4EC98CE6CE3F65C"
      cert_valid_from     = "2023-01-09"
      cert_valid_to       = "2026-01-09"

      country             = "TW"
      state               = "Taipei"
      locality            = "Taipei"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1b:8b:0a:30:44:cc:64:e8:ab:34:10:fd"
      )
}
