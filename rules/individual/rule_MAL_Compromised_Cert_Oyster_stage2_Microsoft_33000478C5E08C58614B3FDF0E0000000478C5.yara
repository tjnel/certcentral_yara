import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_33000478C5E08C58614B3FDF0E0000000478C5 {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-25"
      version             = "1.0"

      hash                = "2a70db4e14fca6d80ce90c21954323299f8c32bc6fabd67744896af4ee8809b7"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "HCCO Retail Ltd."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:78:c5:e0:8c:58:61:4b:3f:df:0e:00:00:00:04:78:c5"
      cert_thumbprint     = "0F84F2FC0600A53AA4BF793A3F54D6B4EF8C3B56"
      cert_valid_from     = "2025-09-25"
      cert_valid_to       = "2025-09-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:78:c5:e0:8c:58:61:4b:3f:df:0e:00:00:00:04:78:c5"
      )
}
