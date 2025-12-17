import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_33000422EDF474C1C6875343EE0000000422ED {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "e2509fc3c350814cfd532b412f7483b43ac8c4a08a35c6a83051856fe95f82fc"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "SOFTWARE DESIGN SERVICES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:04:22:ed:f4:74:c1:c6:87:53:43:ee:00:00:00:04:22:ed"
      cert_thumbprint     = "1562A12483EB66D657C5F35A79A25E0D45323B60"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2025-06-28"

      country             = "US"
      state               = "New York"
      locality            = "Wallkill"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:04:22:ed:f4:74:c1:c6:87:53:43:ee:00:00:00:04:22:ed"
      )
}
