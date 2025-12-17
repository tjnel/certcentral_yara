import "pe"

rule MAL_Compromised_Cert_Parallax_RAT_Microsoft_330006AD4E524073EDED4175E200000006AD4E {
   meta:
      description         = "Detects Parallax RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-12"
      version             = "1.0"

      hash                = "f85cfe9466ca6d61adb2a4b1e498c2e6617ae57d9c21dccf7081bf83f8070778"
      malware             = "Parallax RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PANGEA CIVIL ENGINEERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:ad:4e:52:40:73:ed:ed:41:75:e2:00:00:00:06:ad:4e"
      cert_thumbprint     = "3462069EC4BF0797912DE5D40A8788FF61BCBA8C"
      cert_valid_from     = "2025-12-12"
      cert_valid_to       = "2025-12-15"

      country             = "RO"
      state               = "Ilfov"
      locality            = "POPESTI LEORDENI"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:ad:4e:52:40:73:ed:ed:41:75:e2:00:00:00:06:ad:4e"
      )
}
