import "pe"

rule MAL_Compromised_Cert_Vidar_Microsoft_3300068E61CBE2F34C2A85C551000000068E61 {
   meta:
      description         = "Detects Vidar with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "296333066462e036aa27e2b15300f88099564ac7737bd99af585bfcb4f6cd438"
      malware             = "Vidar"
      malware_type        = "Infostealer"
      malware_notes       = "A popular information stealing malware in 2025. This was likely delivered to victims disguised as a document."

      signer              = "Linkus Corporation"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:8e:61:cb:e2:f3:4c:2a:85:c5:51:00:00:00:06:8e:61"
      cert_thumbprint     = "4969ADC0E8FDB19AC003A625DB2A8523140A8CFE"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2025-12-07"

      country             = "US"
      state               = "Colorado"
      locality            = "Brighton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:8e:61:cb:e2:f3:4c:2a:85:c5:51:00:00:00:06:8e:61"
      )
}
