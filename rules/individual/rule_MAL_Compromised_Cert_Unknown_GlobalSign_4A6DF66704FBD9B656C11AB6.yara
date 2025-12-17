import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_4A6DF66704FBD9B656C11AB6 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-26"
      version             = "1.0"

      hash                = "b3afc517095d0362a32c5655f7572123e5db2e09fe24f6f917b880d6a969c682"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GOLD HARMONY LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4a:6d:f6:67:04:fb:d9:b6:56:c1:1a:b6"
      cert_thumbprint     = "47133B3C7E30C4C8C6D61E8A0AD1A8BB5D09D88A"
      cert_valid_from     = "2025-06-26"
      cert_valid_to       = "2026-06-27"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Herzliya"
      email               = "contactus@goldharmonyltd.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4a:6d:f6:67:04:fb:d9:b6:56:c1:1a:b6"
      )
}
