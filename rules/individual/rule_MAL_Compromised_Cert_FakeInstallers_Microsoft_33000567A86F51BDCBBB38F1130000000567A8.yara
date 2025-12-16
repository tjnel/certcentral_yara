import "pe"

rule MAL_Compromised_Cert_FakeInstallers_Microsoft_33000567A86F51BDCBBB38F1130000000567A8 {
   meta:
      description         = "Detects FakeInstallers with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-11"
      version             = "1.0"

      hash                = "b2d07515d7e1134c413b31babb4d7f3a1c93293fd4a35f02d45dbfce3e210010"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "56 SQUARED PARTNERS LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:67:a8:6f:51:bd:cb:bb:38:f1:13:00:00:00:05:67:a8"
      cert_thumbprint     = "B000F3F7EE582CD023F4E13FEB79A03E666434AC"
      cert_valid_from     = "2025-09-11"
      cert_valid_to       = "2025-09-14"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:67:a8:6f:51:bd:cb:bb:38:f1:13:00:00:00:05:67:a8"
      )
}
