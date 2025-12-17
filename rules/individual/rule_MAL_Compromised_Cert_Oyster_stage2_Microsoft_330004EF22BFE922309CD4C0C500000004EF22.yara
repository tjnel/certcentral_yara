import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_330004EF22BFE922309CD4C0C500000004EF22 {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-21"
      version             = "1.0"

      hash                = "b4a4d565a4d69e1e54557044809fc281591cdc5781126f978df8094467ba59fd"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Mobiquity Technologies, Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:ef:22:bf:e9:22:30:9c:d4:c0:c5:00:00:00:04:ef:22"
      cert_thumbprint     = "979EF570CFF446527C36501AE0BD844256224D92"
      cert_valid_from     = "2025-10-21"
      cert_valid_to       = "2025-10-24"

      country             = "US"
      state               = "New York"
      locality            = "Shoreham"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:ef:22:bf:e9:22:30:9c:d4:c0:c5:00:00:00:04:ef:22"
      )
}
