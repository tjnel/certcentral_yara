import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_33000562AFE8C9483AB03F0ECD0000000562AF {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "c08d5d2647f298c493475fe5ad22b6e6e71f9cd5ee24ed0e62acf98eee119271"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "QUANT QUEST ACADEMY INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:62:af:e8:c9:48:3a:b0:3f:0e:cd:00:00:00:05:62:af"
      cert_thumbprint     = "8041637040E1526CDA4B60EE3C606A22F6B97F4B"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2025-09-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "VAUGHAN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:62:af:e8:c9:48:3a:b0:3f:0e:cd:00:00:00:05:62:af"
      )
}
