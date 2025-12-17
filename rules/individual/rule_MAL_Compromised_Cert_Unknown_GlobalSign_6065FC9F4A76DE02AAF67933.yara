import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_6065FC9F4A76DE02AAF67933 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-20"
      version             = "1.0"

      hash                = "3aa52b8a33682456bae09f25591a076f45a702f1124c7fdddb83f47514ee4b19"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hibernation Holdings, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:65:fc:9f:4a:76:de:02:aa:f6:79:33"
      cert_thumbprint     = "16CA86A50EF4FDB4D44FE0CB0FF463A664E959EC"
      cert_valid_from     = "2025-08-20"
      cert_valid_to       = "2026-08-21"

      country             = "US"
      state               = "New York"
      locality            = "Queens"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:65:fc:9f:4a:76:de:02:aa:f6:79:33"
      )
}
