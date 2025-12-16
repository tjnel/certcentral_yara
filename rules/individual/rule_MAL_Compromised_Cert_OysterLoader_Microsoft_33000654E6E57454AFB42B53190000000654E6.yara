import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_33000654E6E57454AFB42B53190000000654E6 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "326bec0147517a2735cba6dc1604d538f33cbc5ad82a3cf24585a00940bada0f"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "HARTMANN EXECUTIVE CONSULTING LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:54:e6:e5:74:54:af:b4:2b:53:19:00:00:00:06:54:e6"
      cert_thumbprint     = "B99804D9DE416FD030C20A62CA9C6DB1CBA6E4BB"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2025-12-04"

      country             = "US"
      state               = "New York"
      locality            = "MOUNT KISCO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:54:e6:e5:74:54:af:b4:2b:53:19:00:00:00:06:54:e6"
      )
}
