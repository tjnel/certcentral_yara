import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330002185604BDD6D6F3F931C7000000021856 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-15"
      version             = "1.0"

      hash                = "10d25e100989504386b0c45dd2e563441f5b4abbc51e7df7f20bbce88132c71a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TEAM PLAYER SOLUTION LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:18:56:04:bd:d6:d6:f3:f9:31:c7:00:00:00:02:18:56"
      cert_thumbprint     = "E815F32A1A62F193ADBE93C270C3227C8AB18BE2"
      cert_valid_from     = "2025-03-15"
      cert_valid_to       = "2025-03-18"

      country             = "GB"
      state               = "???"
      locality            = "Huntingdon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:18:56:04:bd:d6:d6:f3:f9:31:c7:00:00:00:02:18:56"
      )
}
