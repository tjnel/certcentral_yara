import "pe"

rule MAL_Compromised_Cert_Stealer5000_GlobalSign_47858D45CE2829FA3B600737 {
   meta:
      description         = "Detects Stealer5000 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-08"
      version             = "1.0"

      hash                = "57b6429db74ea920d0cb7fd2e70437d20a688e6e91feb4f117aebae912431f77"
      malware             = "Stealer5000"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Stanki 96"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:85:8d:45:ce:28:29:fa:3b:60:07:37"
      cert_thumbprint     = "BDB91CBA7D916FE09B14647CAD74D3396E0CC618"
      cert_valid_from     = "2025-07-08"
      cert_valid_to       = "2026-07-09"

      country             = "RU"
      state               = "Sverdlovsk Oblast"
      locality            = "Yekaterinburg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:85:8d:45:ce:28:29:fa:3b:60:07:37"
      )
}
