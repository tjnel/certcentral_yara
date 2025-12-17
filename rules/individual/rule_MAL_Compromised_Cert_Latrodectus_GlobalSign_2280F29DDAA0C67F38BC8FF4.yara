import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_2280F29DDAA0C67F38BC8FF4 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "aef5c150cfe8154ed290b293e30d552cfb9b40b3552369345c7c2f135b63aac4"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC KancEra"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "22:80:f2:9d:da:a0:c6:7f:38:bc:8f:f4"
      cert_thumbprint     = "DD818690D1F922E87EE35500434BD7A2D1E9CCBA"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-09"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1127746384810"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "22:80:f2:9d:da:a0:c6:7f:38:bc:8f:f4"
      )
}
