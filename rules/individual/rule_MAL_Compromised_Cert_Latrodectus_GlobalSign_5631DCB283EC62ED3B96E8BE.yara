import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_5631DCB283EC62ED3B96E8BE {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "a66f6e35103338c25ee143c98a6f722c87a663610f147564f99b87468315a1f7"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Xenit"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:31:dc:b2:83:ec:62:ed:3b:96:e8:be"
      cert_thumbprint     = "C519277F61B1BE886D187A0C2E7909D694933250"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-05-17"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1197746744183"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:31:dc:b2:83:ec:62:ed:3b:96:e8:be"
      )
}
