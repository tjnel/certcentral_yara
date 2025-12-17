import "pe"

rule MAL_Compromised_Cert_MonsterV2_Aurotun_Microsoft_3300037399890C4DCE9776933C000000037399 {
   meta:
      description         = "Detects MonsterV2 Aurotun with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-28"
      version             = "1.0"

      hash                = "b660af020b832d2c3d8b1606c76ded2229f22085e667ff3c8d23146ee2993897"
      malware             = "MonsterV2 Aurotun"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MEANINGFUL CONSULTING, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:73:99:89:0c:4d:ce:97:76:93:3c:00:00:00:03:73:99"
      cert_thumbprint     = "02827920DA8306FD2D3220AB2E7D33C587AFC2E9"
      cert_valid_from     = "2025-06-28"
      cert_valid_to       = "2025-07-01"

      country             = "US"
      state               = "Arizona"
      locality            = "Mesa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:73:99:89:0c:4d:ce:97:76:93:3c:00:00:00:03:73:99"
      )
}
