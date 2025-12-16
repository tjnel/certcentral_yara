import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300042BCCEE9EB937D70838E7000000042BCC {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-23"
      version             = "1.0"

      hash                = "bceb8c72c0430797652796514207685c65a182d8285b76b91d219121e7d7e815"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "SOFTWARE DESIGN SERVICES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:04:2b:cc:ee:9e:b9:37:d7:08:38:e7:00:00:00:04:2b:cc"
      cert_thumbprint     = "C1905C62D0B91E1450BD1A24172B4075184F6525"
      cert_valid_from     = "2025-06-23"
      cert_valid_to       = "2025-06-26"

      country             = "US"
      state               = "New York"
      locality            = "Wallkill"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:04:2b:cc:ee:9e:b9:37:d7:08:38:e7:00:00:00:04:2b:cc"
      )
}
