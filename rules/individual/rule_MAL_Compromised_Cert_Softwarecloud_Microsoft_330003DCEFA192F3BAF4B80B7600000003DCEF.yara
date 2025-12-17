import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330003DCEFA192F3BAF4B80B7600000003DCEF {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-28"
      version             = "1.0"

      hash                = "950cdbcbf7024cc600e5e2023ba21210aae506b89786dd6406359df2e01a33af"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:03:dc:ef:a1:92:f3:ba:f4:b8:0b:76:00:00:00:03:dc:ef"
      cert_thumbprint     = "EBE2990928EC847E5D5D0FB006E3D61121CF51FC"
      cert_valid_from     = "2025-05-28"
      cert_valid_to       = "2025-05-31"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:03:dc:ef:a1:92:f3:ba:f4:b8:0b:76:00:00:00:03:dc:ef"
      )
}
