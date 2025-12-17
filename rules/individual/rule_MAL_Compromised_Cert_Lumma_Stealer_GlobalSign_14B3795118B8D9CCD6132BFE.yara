import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_14B3795118B8D9CCD6132BFE {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-11"
      version             = "1.0"

      hash                = "caec63022360e651cc8fae04138cf9e789e7d872369b18e62ed364d49d0de16d"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "RAMAPURA MINERALS PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "14:b3:79:51:18:b8:d9:cc:d6:13:2b:fe"
      cert_thumbprint     = "B743DA976C2834F0E45D7778CE7C6D04DE659BF8"
      cert_valid_from     = "2025-02-11"
      cert_valid_to       = "2026-02-12"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "aloapcorensouy967u@gmail.com"
      rdn_serial_number   = "U14219RJ2006PTC023446"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "14:b3:79:51:18:b8:d9:cc:d6:13:2b:fe"
      )
}
