import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330003C4CB7D52A9E30D0FC9D900000003C4CB {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-22"
      version             = "1.0"

      hash                = "8684805bfce8298df37e3dcc8ec001b4480e3d4e64e19535e8bc1f8796e27d9c"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:c4:cb:7d:52:a9:e3:0d:0f:c9:d9:00:00:00:03:c4:cb"
      cert_thumbprint     = "188C609CCDC98D8D8CFBC35A413756C7C2A9DFB7"
      cert_valid_from     = "2025-05-22"
      cert_valid_to       = "2025-05-25"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:c4:cb:7d:52:a9:e3:0d:0f:c9:d9:00:00:00:03:c4:cb"
      )
}
