import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330005BC0A371369808050410500000005BC0A {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "68a8e1a695cd9c9833977762a8b2fab34ff66c4b8bc23194fdf2a87a7ae30b2d"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Traffer activities around a compromised LinkedIn around, targeting job-seekers with crypto related jobs and spreading fake malicious interview launchers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:bc:0a:37:13:69:80:80:50:41:05:00:00:00:05:bc:0a"
      cert_thumbprint     = "C66BD27CDAD22C48F88A5A7E41B2CFFC68A88256"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2025-10-23"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:bc:0a:37:13:69:80:80:50:41:05:00:00:00:05:bc:0a"
      )
}
