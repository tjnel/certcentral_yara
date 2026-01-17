import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330005F15669E0277C63B7B93100000005F156 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-25"
      version             = "1.0"

      hash                = "5506af207cbaa7f121b54bcb361e88bed172d16dadd329f19141ac157ed576b0"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Traffer activities around a compromised LinkedIn around, targeting job-seekers with crypto related jobs and spreading fake malicious interview launchers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:f1:56:69:e0:27:7c:63:b7:b9:31:00:00:00:05:f1:56"
      cert_thumbprint     = "301B4EA181537E8F8E1C9BB016BC8EB00C70AFD1"
      cert_valid_from     = "2025-10-25"
      cert_valid_to       = "2025-10-28"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:f1:56:69:e0:27:7c:63:b7:b9:31:00:00:00:05:f1:56"
      )
}
