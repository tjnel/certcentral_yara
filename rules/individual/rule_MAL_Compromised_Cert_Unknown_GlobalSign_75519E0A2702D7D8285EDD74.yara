import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_75519E0A2702D7D8285EDD74 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-17"
      version             = "1.0"

      hash                = "addc2ddeadc5ed50f191fdcd5400231da59517ac8dcb470a616cd408ed81a14a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MARKER LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:51:9e:0a:27:02:d7:d8:28:5e:dd:74"
      cert_thumbprint     = "0F5AADCB849CD128144C6F54B811406691C52CF7"
      cert_valid_from     = "2025-03-17"
      cert_valid_to       = "2026-03-18"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1097847091220"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:51:9e:0a:27:02:d7:d8:28:5e:dd:74"
      )
}
