import "pe"

rule MAL_Compromised_Cert_NitrogenLoader_GlobalSign_55BBAE7D7C8BCC0026AADD4C {
   meta:
      description         = "Detects NitrogenLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-17"
      version             = "1.0"

      hash                = "c8e04a01432e56f1d9290f828f54cc683c50bfe656cf69e28549279df2b54c38"
      malware             = "NitrogenLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MAKENI LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:bb:ae:7d:7c:8b:cc:00:26:aa:dd:4c"
      cert_thumbprint     = "25263D4932AEADBDCD36677100383D13D6A7312A"
      cert_valid_from     = "2025-02-17"
      cert_valid_to       = "2026-02-18"

      country             = "KE"
      state               = "Kitui"
      locality            = "Kitui"
      email               = "???"
      rdn_serial_number   = "CPR/2015/200478"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:bb:ae:7d:7c:8b:cc:00:26:aa:dd:4c"
      )
}
