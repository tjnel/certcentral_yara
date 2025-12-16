import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_33000576F970BACFD97EC1EBD90000000576F9 {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-24"
      version             = "1.0"

      hash                = "d19a497670314a3bbff5bc958db3eacfe591c04f866f779cbc06e0f0f48b991f"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "HCCO Retail Ltd."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:76:f9:70:ba:cf:d9:7e:c1:eb:d9:00:00:00:05:76:f9"
      cert_thumbprint     = "87F20D0095F9A8D6A187A6B08A14312B2DD72081"
      cert_valid_from     = "2025-09-24"
      cert_valid_to       = "2025-09-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:76:f9:70:ba:cf:d9:7e:c1:eb:d9:00:00:00:05:76:f9"
      )
}
