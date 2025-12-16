import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_Microsoft_33000462E2BD9A0ADBEEA1F0290000000462E2 {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-18"
      version             = "1.0"

      hash                = "08c3ea261d7849bb91506dc111c348a6dde3bc6f35a95470e4d650bd3513c7c5"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IMMEUBLES DAVECLO INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:62:e2:bd:9a:0a:db:ee:a1:f0:29:00:00:00:04:62:e2"
      cert_thumbprint     = "27ABDE65ADE5BDA2A1EA31B33A683B25CB62CDF9"
      cert_valid_from     = "2025-09-18"
      cert_valid_to       = "2025-09-21"

      country             = "CA"
      state               = "Québec"
      locality            = "Chambly"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:62:e2:bd:9a:0a:db:ee:a1:f0:29:00:00:00:04:62:e2"
      )
}
