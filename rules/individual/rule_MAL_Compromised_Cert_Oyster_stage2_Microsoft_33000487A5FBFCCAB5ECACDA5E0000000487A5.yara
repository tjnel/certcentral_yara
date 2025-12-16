import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_33000487A5FBFCCAB5ECACDA5E0000000487A5 {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "f21483536cbd1fa4f5cb1e996adbe6a82522ca90e14975f6172794995ed9e9a2"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "BRANCH INVESTMENTS HAWAII LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:87:a5:fb:fc:ca:b5:ec:ac:da:5e:00:00:00:04:87:a5"
      cert_thumbprint     = "8763137375E2D46397DA8AD1043F9278F5B7FA0F"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2025-10-03"

      country             = "US"
      state               = "Hawaii"
      locality            = "Kaneohe"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:87:a5:fb:fc:ca:b5:ec:ac:da:5e:00:00:00:04:87:a5"
      )
}
