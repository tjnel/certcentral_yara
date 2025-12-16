import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002E0A058BFA02E8C1B09A900000002E0A0 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-13"
      version             = "1.0"

      hash                = "9794fc55b2fc94fed0ae3ab774c5bffec4ef4a477e670d598e3323d5df116ffc"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Mayra Software, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:e0:a0:58:bf:a0:2e:8c:1b:09:a9:00:00:00:02:e0:a0"
      cert_thumbprint     = "F539B4E7AA9486EDF160F4ED15C3D77B67283DCE"
      cert_valid_from     = "2025-05-13"
      cert_valid_to       = "2025-05-16"

      country             = "US"
      state               = "Missouri"
      locality            = "Saint Charles"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:e0:a0:58:bf:a0:2e:8c:1b:09:a9:00:00:00:02:e0:a0"
      )
}
