import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_34D56E27C24CA3EDD5431BC93E9F3DB2 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-01"
      version             = "1.0"

      hash                = "11d342f01a9deb1d8dbeb8030255fdd5ec4ba4f5c9029d38e0c71d3e885f6ddf"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "International Holdings, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "34:d5:6e:27:c2:4c:a3:ed:d5:43:1b:c9:3e:9f:3d:b2"
      cert_thumbprint     = "679488428F0072BAF75CCB63F3FBD18D60E04C9C"
      cert_valid_from     = "2025-10-01"
      cert_valid_to       = "2026-10-01"

      country             = "US"
      state               = "Missouri"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "LC1788569"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "34:d5:6e:27:c2:4c:a3:ed:d5:43:1b:c9:3e:9f:3d:b2"
      )
}
