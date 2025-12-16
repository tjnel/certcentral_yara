import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_330005A96D055159B905B6967600000005A96D {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-28"
      version             = "1.0"

      hash                = "9ce7fa41d8088472dcda120012d025f16c638c57511ac4b337f16893c4580105"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Assurance Property Management L.L.C."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:a9:6d:05:51:59:b9:05:b6:96:76:00:00:00:05:a9:6d"
      cert_thumbprint     = "AC1127E674EF33B623576595AAB7788ABFF420F4"
      cert_valid_from     = "2025-09-28"
      cert_valid_to       = "2025-10-01"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:a9:6d:05:51:59:b9:05:b6:96:76:00:00:00:05:a9:6d"
      )
}
