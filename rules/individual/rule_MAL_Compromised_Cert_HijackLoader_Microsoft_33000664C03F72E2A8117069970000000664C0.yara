import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_33000664C03F72E2A8117069970000000664C0 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-14"
      version             = "1.0"

      hash                = "c04722211255de54faafc17886be1a4bd3fb78dda3854f43d17047689a1d9a32"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FOCUS DIGITAL AGENCY SP Z O O"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:64:c0:3f:72:e2:a8:11:70:69:97:00:00:00:06:64:c0"
      cert_thumbprint     = "9A32D9BFBB9D39045195D692411292111ACDD221"
      cert_valid_from     = "2026-01-14"
      cert_valid_to       = "2026-01-17"

      country             = "PL"
      state               = "Mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:64:c0:3f:72:e2:a8:11:70:69:97:00:00:00:06:64:c0"
      )
}
