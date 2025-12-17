import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_3300050B6DF0AE2F05DF3E2D8F000000050B6D {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-26"
      version             = "1.0"

      hash                = "a442eb87e36814f33635c971290576586980f77523d223174da0719ca35aa2e9"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THROGGS NECK PETS INCORPORATED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:0b:6d:f0:ae:2f:05:df:3e:2d:8f:00:00:00:05:0b:6d"
      cert_thumbprint     = "8F771C60AD411E4061EB893609A49A6AFF392314"
      cert_valid_from     = "2025-10-26"
      cert_valid_to       = "2025-10-29"

      country             = "US"
      state               = "New York"
      locality            = "BRONX"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:0b:6d:f0:ae:2f:05:df:3e:2d:8f:00:00:00:05:0b:6d"
      )
}
