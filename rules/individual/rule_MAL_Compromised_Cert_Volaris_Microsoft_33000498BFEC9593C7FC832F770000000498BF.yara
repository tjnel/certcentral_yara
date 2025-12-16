import "pe"

rule MAL_Compromised_Cert_Volaris_Microsoft_33000498BFEC9593C7FC832F770000000498BF {
   meta:
      description         = "Detects Volaris with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "71415f0855b5e95b8e73a39b6be65f8c2a775893689775aec452708045ca7c13"
      malware             = "Volaris"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DELPA SOLUTIONS INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:04:98:bf:ec:95:93:c7:fc:83:2f:77:00:00:00:04:98:bf"
      cert_thumbprint     = "E00FD161632E05FBE6A99EE0A1E2199390C05F18"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2025-07-28"

      country             = "CA"
      state               = "Québec"
      locality            = "STE ANNE DE BELLEVUE"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:04:98:bf:ec:95:93:c7:fc:83:2f:77:00:00:00:04:98:bf"
      )
}
