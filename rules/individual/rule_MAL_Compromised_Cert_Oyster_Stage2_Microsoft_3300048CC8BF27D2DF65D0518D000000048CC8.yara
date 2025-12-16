import "pe"

rule MAL_Compromised_Cert_Oyster_Stage2_Microsoft_3300048CC8BF27D2DF65D0518D000000048CC8 {
   meta:
      description         = "Detects Oyster_Stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "c41f42e11e699f45a77ac4e8aef455a07b052180863748f96589d45525e250f6"
      malware             = "Oyster_Stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "CARLMICH MANAGEMENT, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:8c:c8:bf:27:d2:df:65:d0:51:8d:00:00:00:04:8c:c8"
      cert_thumbprint     = "3E6A5628B3EF9CD95825FAD59BA748C9C85A3F04"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2025-10-03"

      country             = "US"
      state               = "Michigan"
      locality            = "West Bloomfield"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:8c:c8:bf:27:d2:df:65:d0:51:8d:00:00:00:04:8c:c8"
      )
}
