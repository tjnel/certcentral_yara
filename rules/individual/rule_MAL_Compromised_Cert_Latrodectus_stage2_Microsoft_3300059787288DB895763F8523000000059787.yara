import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_3300059787288DB895763F8523000000059787 {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-22"
      version             = "1.0"

      hash                = "44a26915bfe1a0f2823d81c08e9d9a96aab65ca73fa9186d09781b2a447e77b6"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IMMEUBLES DAVECLO INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:97:87:28:8d:b8:95:76:3f:85:23:00:00:00:05:97:87"
      cert_thumbprint     = "BA71DD785DF6EBA93AD7E456B6888560B8F1D280"
      cert_valid_from     = "2025-09-22"
      cert_valid_to       = "2025-09-25"

      country             = "CA"
      state               = "Québec"
      locality            = "Chambly"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:97:87:28:8d:b8:95:76:3f:85:23:00:00:00:05:97:87"
      )
}
