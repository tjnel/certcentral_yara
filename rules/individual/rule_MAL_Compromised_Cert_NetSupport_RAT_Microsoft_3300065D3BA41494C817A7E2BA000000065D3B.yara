import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_3300065D3BA41494C817A7E2BA000000065D3B {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-03"
      version             = "1.0"

      hash                = "c260577f01c09fb0076fe3990d809964848e40930ac53070bab4e27da3ca2a81"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GROUPE PROMO-STAFF RTM INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:5d:3b:a4:14:94:c8:17:a7:e2:ba:00:00:00:06:5d:3b"
      cert_thumbprint     = "BF4D7A7AA0414C7F006E8BA3FDA5DF56A7F945CD"
      cert_valid_from     = "2025-12-03"
      cert_valid_to       = "2025-12-06"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Philippe"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:5d:3b:a4:14:94:c8:17:a7:e2:ba:00:00:00:06:5d:3b"
      )
}
