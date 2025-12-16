import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002E6C11CDD113F485DE83C00000002E6C1 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-15"
      version             = "1.0"

      hash                = "b724dba5af1f13d3d01cdae83f75946153ca18f5d7da16ec97070d3a6bd4b9f8"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Mayra Software, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:e6:c1:1c:dd:11:3f:48:5d:e8:3c:00:00:00:02:e6:c1"
      cert_thumbprint     = "E2E5893AE8851B62B517882D9C6886947819F7DC"
      cert_valid_from     = "2025-05-15"
      cert_valid_to       = "2025-05-18"

      country             = "US"
      state               = "Missouri"
      locality            = "Saint Charles"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:e6:c1:1c:dd:11:3f:48:5d:e8:3c:00:00:00:02:e6:c1"
      )
}
