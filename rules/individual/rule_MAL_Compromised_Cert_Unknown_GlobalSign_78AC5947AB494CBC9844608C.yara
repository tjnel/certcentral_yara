import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_78AC5947AB494CBC9844608C {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-15"
      version             = "1.0"

      hash                = "420272ca013384b3b207692122d137e7ba58fc45f4d09741faebd55a1d1db5b4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "X PROGRAMM LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "78:ac:59:47:ab:49:4c:bc:98:44:60:8c"
      cert_thumbprint     = "2010AF985994BDDAD5183E12C17B36DD9EA973A2"
      cert_valid_from     = "2025-08-15"
      cert_valid_to       = "2028-08-15"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "xprogrammltd@proton.me"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "78:ac:59:47:ab:49:4c:bc:98:44:60:8c"
      )
}
