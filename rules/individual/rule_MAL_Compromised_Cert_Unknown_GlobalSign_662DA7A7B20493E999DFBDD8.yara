import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_662DA7A7B20493E999DFBDD8 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "6ae8c50e3b800a6a0bff787e1e24dbc84fb8f5138e5516ebbdc17f980b471512"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SPARROW TIDE LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:2d:a7:a7:b2:04:93:e9:99:df:bd:d8"
      cert_thumbprint     = "8D4FB4A66FD31E36515B5E54D48F31B7715B8AF9"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "support@sparowtideltd.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:2d:a7:a7:b2:04:93:e9:99:df:bd:d8"
      )
}
