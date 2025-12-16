import "pe"

rule MAL_Compromised_Cert_QuasarRAT_Microsoft_33000201B5D72372EE416F0D8F0000000201B5 {
   meta:
      description         = "Detects QuasarRAT with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-08"
      version             = "1.0"

      hash                = "f1e99a7e9c48ecefd988f244085bd291f7d2c06e081338a9c104e8294ccb01bd"
      malware             = "QuasarRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "InLine"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:01:b5:d7:23:72:ee:41:6f:0d:8f:00:00:00:02:01:b5"
      cert_thumbprint     = "91C71CD1B81D99B0B51D1EC542A4FB27BBBF42E2"
      cert_valid_from     = "2025-03-08"
      cert_valid_to       = "2025-03-11"

      country             = "KR"
      state               = "South Gyeongsang"
      locality            = "Gimhae-si"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:01:b5:d7:23:72:ee:41:6f:0d:8f:00:00:00:02:01:b5"
      )
}
