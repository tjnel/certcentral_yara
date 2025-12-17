import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_30A7B6A13EC200A92A763D20 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-03"
      version             = "1.0"

      hash                = "fc3471e819eafc1640b51c5c8d4bd36db60dc96d912769fa0dfd619f3ec6ff09"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Advik Tech Corporation"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "30:a7:b6:a1:3e:c2:00:a9:2a:76:3d:20"
      cert_thumbprint     = "6751696EEBB3C3D10485609FB34405DE444811F0"
      cert_valid_from     = "2024-12-03"
      cert_valid_to       = "2025-12-04"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Surrey"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "30:a7:b6:a1:3e:c2:00:a9:2a:76:3d:20"
      )
}
