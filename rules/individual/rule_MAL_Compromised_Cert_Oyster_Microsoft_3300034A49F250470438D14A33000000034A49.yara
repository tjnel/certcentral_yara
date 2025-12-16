import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_3300034A49F250470438D14A33000000034A49 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "e9e5311fbf76eea22c42daa381074feecb745020db473184e6236f9a08816925"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Micros in Action, Incorporated"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:4a:49:f2:50:47:04:38:d1:4a:33:00:00:00:03:4a:49"
      cert_thumbprint     = "CF798CFDD81C09378349DC8A9331C144E3797CBE"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2025-06-15"

      country             = "US"
      state               = "North Carolina"
      locality            = "Mocksville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:4a:49:f2:50:47:04:38:d1:4a:33:00:00:00:03:4a:49"
      )
}
