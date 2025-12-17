import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300034A34A1F69D8624B367CE000000034A34 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "06a09302c3d5e0ec99a94c13b05a599b5042a6a37e2c28cb7b44921bbed63af7"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "FRONTERA SOFTWARE LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:4a:34:a1:f6:9d:86:24:b3:67:ce:00:00:00:03:4a:34"
      cert_thumbprint     = "F89A5B8C8803AD685D2693B69119563BC909ACD3"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2025-06-15"

      country             = "US"
      state               = "New York"
      locality            = "BROOKLYN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:4a:34:a1:f6:9d:86:24:b3:67:ce:00:00:00:03:4a:34"
      )
}
