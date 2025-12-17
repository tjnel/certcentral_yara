import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_48C2F340350A31E335150ED8 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-06"
      version             = "1.0"

      hash                = "096e2d456e34c5ccdbc1c846978c40c67f615a64766154b0be62d94adb935a2a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BLACKIT LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "48:c2:f3:40:35:0a:31:e3:35:15:0e:d8"
      cert_thumbprint     = "190B7DB5D9234730591F8E245EEDB2F04CAC6461"
      cert_valid_from     = "2025-09-06"
      cert_valid_to       = "2026-06-19"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "48:c2:f3:40:35:0a:31:e3:35:15:0e:d8"
      )
}
