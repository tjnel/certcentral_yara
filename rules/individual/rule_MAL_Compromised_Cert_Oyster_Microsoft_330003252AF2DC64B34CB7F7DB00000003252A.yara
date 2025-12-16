import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330003252AF2DC64B34CB7F7DB00000003252A {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-06"
      version             = "1.0"

      hash                = "daa4ca6b3a4d567eac51b70921a9d6254884477bf5454f966d0ef412c6f0e443"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "GALVIN & ASSOCIATES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:25:2a:f2:dc:64:b3:4c:b7:f7:db:00:00:00:03:25:2a"
      cert_thumbprint     = "802BB60E5A6C41D66D4BD76E5A62474BF2CBCDB7"
      cert_valid_from     = "2025-06-06"
      cert_valid_to       = "2025-06-09"

      country             = "US"
      state               = "New York"
      locality            = "NEW YORK"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:25:2a:f2:dc:64:b3:4c:b7:f7:db:00:00:00:03:25:2a"
      )
}
