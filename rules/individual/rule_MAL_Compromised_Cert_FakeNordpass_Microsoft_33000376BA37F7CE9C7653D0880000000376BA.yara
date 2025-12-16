import "pe"

rule MAL_Compromised_Cert_FakeNordpass_Microsoft_33000376BA37F7CE9C7653D0880000000376BA {
   meta:
      description         = "Detects FakeNordpass with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-23"
      version             = "1.0"

      hash                = "f85a155d3f75cab12843688f02cec2774cb952c8e020cf764be181c81973e59b"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BLUESTEM PIPE & METAL, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:76:ba:37:f7:ce:9c:76:53:d0:88:00:00:00:03:76:ba"
      cert_thumbprint     = "278A075F957D76FDC6100AB93CD75FE59DB9F19C"
      cert_valid_from     = "2025-04-23"
      cert_valid_to       = "2025-04-26"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Oklahoma City"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:76:ba:37:f7:ce:9c:76:53:d0:88:00:00:00:03:76:ba"
      )
}
