import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330005D52D7502E06772B1B3E100000005D52D {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-30"
      version             = "1.0"

      hash                = "637c9408e573f1173b40a51a8b4dac0632723da2cc8dee816dc8134c07785c90"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Management Performance Auto Service Ltd."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:d5:2d:75:02:e0:67:72:b1:b3:e1:00:00:00:05:d5:2d"
      cert_thumbprint     = "4030C41170A40253C55A6202D7B724E13CBAB1A1"
      cert_valid_from     = "2025-10-30"
      cert_valid_to       = "2025-11-02"

      country             = "CA"
      state               = "Prince Edward Island"
      locality            = "Charlottetown"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:d5:2d:75:02:e0:67:72:b1:b3:e1:00:00:00:05:d5:2d"
      )
}
