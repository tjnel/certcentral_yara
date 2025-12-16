import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002F0241B84F150B7CB168E00000002F024 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-18"
      version             = "1.0"

      hash                = "2c8530fdece9bd09453fbdd189823aa6fcdf0b23496ac6950fbdf95e41ea444b"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:f0:24:1b:84:f1:50:b7:cb:16:8e:00:00:00:02:f0:24"
      cert_thumbprint     = "BEC9ED54C1BA4A5D5E9A50DD084B57D342E0A2E9"
      cert_valid_from     = "2025-05-18"
      cert_valid_to       = "2025-05-21"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:f0:24:1b:84:f1:50:b7:cb:16:8e:00:00:00:02:f0:24"
      )
}
