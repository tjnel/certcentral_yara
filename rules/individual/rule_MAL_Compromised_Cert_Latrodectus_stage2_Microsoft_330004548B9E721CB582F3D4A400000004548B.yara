import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_330004548B9E721CB582F3D4A400000004548B {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-14"
      version             = "1.0"

      hash                = "18b680773fb2b58e34166c7694dd9f533e66936d6effa2430d7c7fbaa57e8722"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "QUANT QUEST ACADEMY INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:54:8b:9e:72:1c:b5:82:f3:d4:a4:00:00:00:04:54:8b"
      cert_thumbprint     = "07EEE4B654C49F29131DA4B747E7786E35ED9496"
      cert_valid_from     = "2025-09-14"
      cert_valid_to       = "2025-09-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "VAUGHAN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:54:8b:9e:72:1c:b5:82:f3:d4:a4:00:00:00:04:54:8b"
      )
}
