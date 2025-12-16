import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_3300059AE61DF12BC90C40CC42000000059AE6 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-09"
      version             = "1.0"

      hash                = "fdfae96c3e943c16f7946d820598b2d205395fe7483b5b82e4a9903dc96c1eb1"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "ECHO PADDLES INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:9a:e6:1d:f1:2b:c9:0c:40:cc:42:00:00:00:05:9a:e6"
      cert_thumbprint     = "2CFA6A828A11EC66ED4CD86DF73D25B139A42EED"
      cert_valid_from     = "2025-10-09"
      cert_valid_to       = "2025-10-12"

      country             = "CA"
      state               = "Québec"
      locality            = "Wakefield"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:9a:e6:1d:f1:2b:c9:0c:40:cc:42:00:00:00:05:9a:e6"
      )
}
