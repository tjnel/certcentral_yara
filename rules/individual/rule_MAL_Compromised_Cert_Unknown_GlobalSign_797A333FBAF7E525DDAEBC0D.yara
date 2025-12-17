import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_797A333FBAF7E525DDAEBC0D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "5afc9b30c522545344b315c66f210f789bd0b54ad01617a6291feef466e89a7c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BSZ Group AB"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "79:7a:33:3f:ba:f7:e5:25:dd:ae:bc:0d"
      cert_thumbprint     = "878313CAFA6D0191A4D7341E0EBF8F5C0B191887"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "SE"
      state               = "Stockholm"
      locality            = "Södertälje"
      email               = "info@bszgroup.net"
      rdn_serial_number   = "559131-8992"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "79:7a:33:3f:ba:f7:e5:25:dd:ae:bc:0d"
      )
}
