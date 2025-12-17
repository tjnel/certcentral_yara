import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004FFBC4979498CDBFDF3BB00000004FFBC {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-23"
      version             = "1.0"

      hash                = "e9e53a0f3111e1217c088807f667b3a926b7d7ede12dc124ae814b19e92b001f"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:ff:bc:49:79:49:8c:db:fd:f3:bb:00:00:00:04:ff:bc"
      cert_thumbprint     = "A8E0F8825C651C68A491C2E9D6E0362D56003316"
      cert_valid_from     = "2025-10-23"
      cert_valid_to       = "2025-10-26"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:ff:bc:49:79:49:8c:db:fd:f3:bb:00:00:00:04:ff:bc"
      )
}
