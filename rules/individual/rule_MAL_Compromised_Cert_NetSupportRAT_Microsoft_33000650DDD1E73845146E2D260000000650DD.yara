import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_Microsoft_33000650DDD1E73845146E2D260000000650DD {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-30"
      version             = "1.0"

      hash                = "6684bd671de9dce1e8cfc4d41bf5a4ef3dabc8925eac4a47712b128224518b9e"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "File is dropped from a fake logistics website: https://x.com/malwrhunterteam/status/1995974194006552855?s=20"

      signer              = "RITZ AND JOHNSON BUILDING PARTNERSHIP, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:50:dd:d1:e7:38:45:14:6e:2d:26:00:00:00:06:50:dd"
      cert_thumbprint     = "761C3D17E789A71CA32A8C0C85B8FF769BA05BCF"
      cert_valid_from     = "2025-11-30"
      cert_valid_to       = "2025-12-03"

      country             = "US"
      state               = "Florida"
      locality            = "OCALA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:50:dd:d1:e7:38:45:14:6e:2d:26:00:00:00:06:50:dd"
      )
}
