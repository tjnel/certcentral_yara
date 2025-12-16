import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_33000571E980AABA26C5B271BD0000000571E9 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-22"
      version             = "1.0"

      hash                = "5c797080fa605cab2cd581645f00843f9c91c9c2d0ad4598ccb7886f990c916b"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "DELANEY HOME INSPECTIONS LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:71:e9:80:aa:ba:26:c5:b2:71:bd:00:00:00:05:71:e9"
      cert_thumbprint     = "003075A520624B49542FDBE04DB976D04D2B7A0A"
      cert_valid_from     = "2025-09-22"
      cert_valid_to       = "2025-09-25"

      country             = "US"
      state               = "New York"
      locality            = "Oceanside"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:71:e9:80:aa:ba:26:c5:b2:71:bd:00:00:00:05:71:e9"
      )
}
