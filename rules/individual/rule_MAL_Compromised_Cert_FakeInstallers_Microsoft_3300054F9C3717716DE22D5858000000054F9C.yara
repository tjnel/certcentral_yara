import "pe"

rule MAL_Compromised_Cert_FakeInstallers_Microsoft_3300054F9C3717716DE22D5858000000054F9C {
   meta:
      description         = "Detects FakeInstallers with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-15"
      version             = "1.0"

      hash                = "1d10e0aae7b14c6ebd609d88f9ef4cc4e812ca25d9fd43d075ae4e7c7bd5eb79"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "56 SQUARED PARTNERS LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:4f:9c:37:17:71:6d:e2:2d:58:58:00:00:00:05:4f:9c"
      cert_thumbprint     = "F8478A9A952EE947BE1A1032F60A0D85FE3CF646"
      cert_valid_from     = "2025-09-15"
      cert_valid_to       = "2025-09-18"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:4f:9c:37:17:71:6d:e2:2d:58:58:00:00:00:05:4f:9c"
      )
}
