import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330004A21E6A9A01E65912C57200000004A21E {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "a3b858014d60eaa5b356b7e707a263d98b111b53835ae326cd4e0fb19e7f5b35"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Nitta-Lai Investment Corp."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:a2:1e:6a:9a:01:e6:59:12:c5:72:00:00:00:04:a2:1e"
      cert_thumbprint     = "082EF59E74FC9AAC0A61CAAF9318A562562BB33E"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2025-10-06"

      country             = "CA"
      state               = "Ontario"
      locality            = "Etobicoke"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:a2:1e:6a:9a:01:e6:59:12:c5:72:00:00:00:04:a2:1e"
      )
}
