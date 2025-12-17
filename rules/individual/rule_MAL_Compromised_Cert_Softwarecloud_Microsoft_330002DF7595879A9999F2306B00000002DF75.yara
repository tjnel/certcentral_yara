import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002DF7595879A9999F2306B00000002DF75 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-14"
      version             = "1.0"

      hash                = "7768c7a632653d7c4cdf98db18a342536f046f20ed96259c59bdbdcd77fc8b53"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Mayra Software, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:02:df:75:95:87:9a:99:99:f2:30:6b:00:00:00:02:df:75"
      cert_thumbprint     = "D3E0744037E0D39D4F425A2E703B3DA1162928C1"
      cert_valid_from     = "2025-05-14"
      cert_valid_to       = "2025-05-17"

      country             = "US"
      state               = "Missouri"
      locality            = "Saint Charles"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:02:df:75:95:87:9a:99:99:f2:30:6b:00:00:00:02:df:75"
      )
}
