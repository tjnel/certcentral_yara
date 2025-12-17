import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_019BEEF41E8CE589026DB546 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "7780f4762d9526f0156f3d8b39b833ec7bc2023dc67e4940864ddb0fffe910ff"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Farfield Computing Systems Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "01:9b:ee:f4:1e:8c:e5:89:02:6d:b5:46"
      cert_thumbprint     = "B9ED6FF1ECF8DD8A44E0A0A3B2C9DC351CD72A03"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-25"

      country             = "CA"
      state               = "Ontario"
      locality            = "Kitchener"
      email               = "???"
      rdn_serial_number   = "860519-0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "01:9b:ee:f4:1e:8c:e5:89:02:6d:b5:46"
      )
}
