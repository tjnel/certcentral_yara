import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006782DA6C8B6CE5664F88500000006782D {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-28"
      version             = "1.0"

      hash                = "8cb3a5a1a3ae192018049dcbf37f58678e0c21323f9ddd7e1201d695d1b1826b"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JAMES BARRIERE FOUNDATION FOR THE UNDERPRIVILEGED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:78:2d:a6:c8:b6:ce:56:64:f8:85:00:00:00:06:78:2d"
      cert_thumbprint     = "5411F2062BBB085787A9A65C8FCEED1B47CB7061"
      cert_valid_from     = "2025-11-28"
      cert_valid_to       = "2025-12-01"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:78:2d:a6:c8:b6:ce:56:64:f8:85:00:00:00:06:78:2d"
      )
}
