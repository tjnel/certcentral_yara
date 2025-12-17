import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_694485FC3754D759163719A3 {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-29"
      version             = "1.0"

      hash                = "ad415a5fe368e89c4b00337b00baf6ed8b77c83d27d8f9e0628f1217a6082740"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Onixgroup"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:44:85:fc:37:54:d7:59:16:37:19:a3"
      cert_thumbprint     = "915B12D55360FEA1D66F54BDA021088F061116E7"
      cert_valid_from     = "2025-05-29"
      cert_valid_to       = "2026-05-30"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1227700381336"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:44:85:fc:37:54:d7:59:16:37:19:a3"
      )
}
