import "pe"

rule MAL_Compromised_Cert_Latrodectus_Microsoft_33000468D113BB359F22A815FB0000000468D1 {
   meta:
      description         = "Detects Latrodectus with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-19"
      version             = "1.0"

      hash                = "c92081585c525afba5abcb773c7ca9532fba6ce5e7aca340a226e2b05ff3b0d2"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IMMEUBLES DAVECLO INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:68:d1:13:bb:35:9f:22:a8:15:fb:00:00:00:04:68:d1"
      cert_thumbprint     = "F8036C868223F58E927422BF459A362DC57B645C"
      cert_valid_from     = "2025-09-19"
      cert_valid_to       = "2025-09-22"

      country             = "CA"
      state               = "Québec"
      locality            = "Chambly"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:68:d1:13:bb:35:9f:22:a8:15:fb:00:00:00:04:68:d1"
      )
}
