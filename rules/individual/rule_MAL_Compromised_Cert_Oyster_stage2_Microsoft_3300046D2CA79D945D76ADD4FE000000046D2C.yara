import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_3300046D2CA79D945D76ADD4FE000000046D2C {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-23"
      version             = "1.0"

      hash                = "c66540bc726ae996fdc876819e41cdc0af4bdb092acb16ed5aefe031a3f20403"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "HCCO Retail Ltd."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:6d:2c:a7:9d:94:5d:76:ad:d4:fe:00:00:00:04:6d:2c"
      cert_thumbprint     = "2B271BC5959B537DDF674BED54A605C07C3D5218"
      cert_valid_from     = "2025-09-23"
      cert_valid_to       = "2025-09-26"

      country             = "CA"
      state               = "Ontario"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:6d:2c:a7:9d:94:5d:76:ad:d4:fe:00:00:00:04:6d:2c"
      )
}
