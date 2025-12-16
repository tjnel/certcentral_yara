import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_3300034227859130DB98A2AA4A000000034227 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "cd671cfa42714a6d517476add60690081a16a5c6abaacce25fcb9c5ddf41b7d3"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Micros in Action, Incorporated"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:42:27:85:91:30:db:98:a2:aa:4a:00:00:00:03:42:27"
      cert_thumbprint     = "10F1D072B41F68104AAD99659EE2F97E0D62F37A"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2025-06-13"

      country             = "US"
      state               = "North Carolina"
      locality            = "Mocksville"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:42:27:85:91:30:db:98:a2:aa:4a:00:00:00:03:42:27"
      )
}
