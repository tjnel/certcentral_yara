import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_33000569DCC148A15583BC04790000000569DC {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-11"
      version             = "1.0"

      hash                = "2528df60e55f210a6396dd7740d76afe30d5e9e8684a5b8a02a63bdcb5041bfc"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "QUANT QUEST ACADEMY INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:69:dc:c1:48:a1:55:83:bc:04:79:00:00:00:05:69:dc"
      cert_thumbprint     = "AE97AE942C0E27D52CB45A91DDC785B9EF69E3CB"
      cert_valid_from     = "2025-09-11"
      cert_valid_to       = "2025-09-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "VAUGHAN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:69:dc:c1:48:a1:55:83:bc:04:79:00:00:00:05:69:dc"
      )
}
