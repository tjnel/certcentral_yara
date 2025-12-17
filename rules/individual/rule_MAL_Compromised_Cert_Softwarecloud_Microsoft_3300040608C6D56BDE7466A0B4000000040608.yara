import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300040608C6D56BDE7466A0B4000000040608 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-15"
      version             = "1.0"

      hash                = "0750a3fd8946a79ebd9d7279b523383764032185b2e617b932b1d8a8d1f3219c"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "FRONTERA SOFTWARE LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:04:06:08:c6:d5:6b:de:74:66:a0:b4:00:00:00:04:06:08"
      cert_thumbprint     = "3C8E7FABCFC78AEDC996CC605FFB96B64ECF60CB"
      cert_valid_from     = "2025-06-15"
      cert_valid_to       = "2025-06-18"

      country             = "US"
      state               = "New York"
      locality            = "BROOKLYN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:04:06:08:c6:d5:6b:de:74:66:a0:b4:00:00:00:04:06:08"
      )
}
