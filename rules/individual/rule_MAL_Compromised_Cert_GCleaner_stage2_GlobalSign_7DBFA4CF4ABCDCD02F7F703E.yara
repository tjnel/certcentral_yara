import "pe"

rule MAL_Compromised_Cert_GCleaner_stage2_GlobalSign_7DBFA4CF4ABCDCD02F7F703E {
   meta:
      description         = "Detects GCleaner_stage2 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-03"
      version             = "1.0"

      hash                = "f35ebf7bb19f45a1eeff06c63713510730a80bbc9ff395f21185d0e0ffb833c1"
      malware             = "GCleaner_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Longshang Inc"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7d:bf:a4:cf:4a:bc:dc:d0:2f:7f:70:3e"
      cert_thumbprint     = "26DFD16A2C5140A44DC33D6A8C973E137D867078"
      cert_valid_from     = "2025-11-03"
      cert_valid_to       = "2026-11-04"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "20258080311"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7d:bf:a4:cf:4a:bc:dc:d0:2f:7f:70:3e"
      )
}
