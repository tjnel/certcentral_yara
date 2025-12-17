import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_0B02515F2E732BE0C19084A8 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-02"
      version             = "1.0"

      hash                = "a399bf56687bc04707fc1cc7771725f500d5d70d4fcdfbc3462d6b1ff37b8a9d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Freshmix"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0b:02:51:5f:2e:73:2b:e0:c1:90:84:a8"
      cert_thumbprint     = "5DFBDF6BFF746A18C7A44F4F16881AE3D83FA540"
      cert_valid_from     = "2025-04-02"
      cert_valid_to       = "2026-04-03"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1187746137215"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0b:02:51:5f:2e:73:2b:e0:c1:90:84:a8"
      )
}
