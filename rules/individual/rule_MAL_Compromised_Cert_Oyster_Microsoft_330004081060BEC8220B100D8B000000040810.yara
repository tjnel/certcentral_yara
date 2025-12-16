import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330004081060BEC8220B100D8B000000040810 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-15"
      version             = "1.0"

      hash                = "0bcdbd79c13fc50955804d0f2666c878542157fc3d4987d18d13c72e9697209e"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "IceCube Software, Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:04:08:10:60:be:c8:22:0b:10:0d:8b:00:00:00:04:08:10"
      cert_thumbprint     = "98FF3C03623F77A5A43D4C32A39A1CBE9DF42DD7"
      cert_valid_from     = "2025-06-15"
      cert_valid_to       = "2025-06-18"

      country             = "US"
      state               = "North Carolina"
      locality            = "Davidson"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:04:08:10:60:be:c8:22:0b:10:0d:8b:00:00:00:04:08:10"
      )
}
