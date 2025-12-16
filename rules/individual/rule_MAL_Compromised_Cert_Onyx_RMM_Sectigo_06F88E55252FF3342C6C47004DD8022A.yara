import "pe"

rule MAL_Compromised_Cert_Onyx_RMM_Sectigo_06F88E55252FF3342C6C47004DD8022A {
   meta:
      description         = "Detects Onyx RMM with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-06"
      version             = "1.0"

      hash                = "bd12c6d8caeb7e4a473c37878435e812db9a379b435ac1aa66b41e1036eb02eb"
      malware             = "Onyx RMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISSY'S CREDIBLE CLEANING LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "06:f8:8e:55:25:2f:f3:34:2c:6c:47:00:4d:d8:02:2a"
      cert_thumbprint     = "D181F621AE2CBD299592A7DCE1AB4C4E9A9E9364"
      cert_valid_from     = "2025-10-06"
      cert_valid_to       = "2026-10-06"

      country             = "US"
      state               = "Florida"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "06:f8:8e:55:25:2f:f3:34:2c:6c:47:00:4d:d8:02:2a"
      )
}
