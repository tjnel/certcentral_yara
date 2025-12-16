import "pe"

rule MAL_Compromised_Cert_SystemBC_GlobalSign_45C03D0AF72D5526BA65E57E {
   meta:
      description         = "Detects SystemBC with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-23"
      version             = "1.0"

      hash                = "c69ab262ac3f73277c4b9a777a408f57feb618e2e00bc2e66e8d97274083c742"
      malware             = "SystemBC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AESUMON SOFTWARE Incorporated"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "45:c0:3d:0a:f7:2d:55:26:ba:65:e5:7e"
      cert_thumbprint     = "F3D17D0531B802F20713CA2704873545D8209B6C"
      cert_valid_from     = "2024-09-23"
      cert_valid_to       = "2025-09-24"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "1091701-0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "45:c0:3d:0a:f7:2d:55:26:ba:65:e5:7e"
      )
}
