import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_3300050DC76B5EAA3EBF6729AB000000050DC7 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "a9522fbe86712f17679ad5d900408cb1258886896c219bd647253ef54c36648a"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "INDIANA PROPERTY RIGHTS ALLIANCE, INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:0d:c7:6b:5e:aa:3e:bf:67:29:ab:00:00:00:05:0d:c7"
      cert_thumbprint     = "B1C1B565F1B670A6D1BB4FA9173FCD85BAFC6639"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2025-10-31"

      country             = "US"
      state               = "Indiana"
      locality            = "Indianapolis"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:0d:c7:6b:5e:aa:3e:bf:67:29:ab:00:00:00:05:0d:c7"
      )
}
