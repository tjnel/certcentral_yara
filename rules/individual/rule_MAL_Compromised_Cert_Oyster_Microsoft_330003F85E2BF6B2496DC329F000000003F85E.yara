import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330003F85E2BF6B2496DC329F000000003F85E {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "dae9df9ce0f5286cfe871fda680e4de440c8444a44ceb434c28d5ccf786f5e8d"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "GALVIN & ASSOCIATES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:03:f8:5e:2b:f6:b2:49:6d:c3:29:f0:00:00:00:03:f8:5e"
      cert_thumbprint     = "F88EF64C0B48D03ACC8F4916A9331BF0B961AC85"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2025-06-08"

      country             = "US"
      state               = "New York"
      locality            = "NEW YORK"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:03:f8:5e:2b:f6:b2:49:6d:c3:29:f0:00:00:00:03:f8:5e"
      )
}
