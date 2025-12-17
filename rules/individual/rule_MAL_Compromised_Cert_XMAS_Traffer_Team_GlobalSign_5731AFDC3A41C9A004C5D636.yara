import "pe"

rule MAL_Compromised_Cert_XMAS_Traffer_Team_GlobalSign_5731AFDC3A41C9A004C5D636 {
   meta:
      description         = "Detects XMAS Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "f93cfed22f012735e4deffc5b95d32747d18e58f9853a700317d6a552edfd719"
      malware             = "XMAS Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Yubileiny"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:31:af:dc:3a:41:c9:a0:04:c5:d6:36"
      cert_thumbprint     = "1D1DF932EC5AEED2EFD08BFE7A49CD5CEAACA275"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2026-04-17"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Podolsk"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:31:af:dc:3a:41:c9:a0:04:c5:d6:36"
      )
}
